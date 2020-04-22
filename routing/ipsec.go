// Copyright (C) 2019 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routing

import (
	"bytes"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ipsecProvider struct {
	ipipIfs map[string][]uint32
	l       *logrus.Entry
	s       *Server
}

func newIPsecProvider(s *Server) (p *ipsecProvider) {
	p = &ipsecProvider{
		ipipIfs: make(map[string][]uint32),
		l:       s.l.WithField("connectivity", "ipsec"),
		s:       s,
	}
	return p
}

func ipToSafeString(addr net.IP) string {
	return strings.ReplaceAll(strings.ReplaceAll(addr.String(), ".", "_"), ":", "_")
}

func profileName(srcNodeAddr, destNodeAddr net.IP) string {
	return "pr_" + ipToSafeString(srcNodeAddr) + "_to_" + ipToSafeString(destNodeAddr)
}

func (p ipsecProvider) setupTunnels(destNodeAddr net.IP, isV4 bool) (err error) {
	nodeIP, _, err := p.s.getNodeIPNet()
	if err != nil {
		return errors.Wrapf(err, "Error getting node ip")
	}

	if !isV4 || nodeIP.To4() == nil || destNodeAddr.To4() == nil {
		return errors.New("IPv6 not supported with IPsec at this time")
	}

	psk := os.Getenv("CALICOVPP_IPSEC_IKEV2_PSK")
	if psk == "" {
		return errors.New("IKEv2 PSK not configured: nothing found in CALICOVPP_IPSEC_IKEV2_PSK environment variable")
	}

	extraAddressCount, _ := strconv.ParseInt(os.Getenv("CALICOVPP_IPSEC_ASSUME_EXTRA_ADDRESSES"), 10, 8)

	for i := int64(0); i < 1+extraAddressCount; i++ {
		src := net.IP(append([]byte(nil), nodeIP.To4()...))
		src[2] += byte(i)
		dst := net.IP(append([]byte(nil), destNodeAddr.To4()...))
		dst[2] += byte(i)
		p.l.Infof("Adding IPsec tunnel from %s to %s", src, dst)
		swIfIndex, err := p.setupOneTunnel(src, dst, psk)
		if err != nil {
			return errors.Wrapf(err, "error configuring ipsec tunnel from %s to %s", src.String(), dst.String())
		}
		p.ipipIfs[destNodeAddr.String()] = append(p.ipipIfs[destNodeAddr.String()], swIfIndex)
	}

	return nil
}

func (p ipsecProvider) setupOneTunnel(src, dst net.IP, psk string) (tunSwIfIndex uint32, err error) {
	swIfIndex, err := p.s.vpp.AddIpipTunnel(src, dst, true, 0)
	if err != nil {
		return 0, errors.Wrapf(err, "Error adding ipip tunnel %s -> %s", src.String(), dst.String())
	}

	err = p.s.vpp.AddNat44OutsideInterface(swIfIndex)
	if err != nil {
		// TODO : delete tunnel
		return 0, errors.Wrapf(err, "Error setting ipip interface out for nat44")
	}
	p.l.Infof("ipip tunnel from %s to %s created with index %d", src.String(), dst.String(), swIfIndex)

	err = p.s.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
	if err != nil {
		// TODO : delete tunnel
		return 0, errors.Wrapf(err, "Error seting ipip tunnel %d unnumbered: %s", swIfIndex)
	}

	// Always enable GSO feature on IPIP tunnel, only a tiny negative effect on perf if GSO is not enabled on the taps
	err = p.s.vpp.EnableGSOFeature(swIfIndex)
	if err != nil {
		// TODO : delete tunnel
		return 0, errors.Wrapf(err, "Error enabling gso for ipip interface")
	}

	// Add and configure related IKE profile
	profile := profileName(src, dst)
	err = p.s.vpp.AddIKEv2Profile(profile)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.s.vpp.SetIKEv2PSKAuth(profile, psk)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.s.vpp.SetIKEv2LocalIDAddress(profile, src)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.s.vpp.SetIKEv2RemoteIDAddress(profile, dst)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	err = p.s.vpp.SetIKEv2PermissiveTrafficSelectors(profile)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	p.l.Infof("IKE: Profile %s = swifindex %d", profile, swIfIndex)
	err = p.s.vpp.SetIKEv2TunnelInterface(profile, swIfIndex)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	// Compare addresses lexicographically to select an initiator
	if bytes.Compare(src.To4(), dst.To4()) > 0 {
		p.l.Infof("IKE: Set responder %s->%s", src.String(), dst.String())
		err = p.s.vpp.SetIKEv2Responder(profile, config.DataInterfaceSwIfIndex, dst)
		if err != nil {
			return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
		}

		err = p.s.vpp.SetIKEv2DefaultTransforms(profile)
		if err != nil {
			return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
		}

		err = p.s.vpp.IKEv2Initiate(profile)
		if err != nil {
			return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
		}
	}

	// Wait for IPsec connection to be established to bring tunnel up
	go p.waitForIPsecSA(profile, swIfIndex)

	return swIfIndex, nil
}

func (p *ipsecProvider) waitForIPsecSA(profile string, ipipInterface uint32) {
	for {
		time.Sleep(time.Second)
		iface, err := p.s.vpp.GetInterfaceDetails(ipipInterface)
		if err != nil {
			p.l.Errorf("Cannot get IPIP tunnel %d status", ipipInterface)
			return
		}
		if !iface.IsUp {
			p.l.Debugf("IPIP tunnel %d still down", ipipInterface)
			continue
		}
		p.l.Debugf("Profile %s tunnel now up", profile)
		return
	}
}

func (p ipsecProvider) addConnectivity(dst net.IPNet, destNodeAddr net.IP, isV4 bool) (err error) {
	p.l.Debugf("Adding IPsec connectivity to %s via %s", dst.String(), destNodeAddr.String())

	if _, found := p.ipipIfs[destNodeAddr.String()]; !found {
		err = p.setupTunnels(destNodeAddr, isV4)
		if err != nil {
			return errors.Wrap(err, "Error configuring IPsec tunnels")
		}
	}
	swIfIndices := p.ipipIfs[destNodeAddr.String()]

	p.l.Debugf("Adding ipip tunnel route to %s via swIfIndices %v", dst.IP.String(), swIfIndices)
	e := p.s.vpp.RouteMAdd(&types.MRoute{
		Dst:       &dst,
		Gw:        nil,
		SwIfIndex: swIfIndices,
	})
	if e != nil {
		err = e
		p.l.Errorf("Error setting route in VPP: %v", err)
	}
	return errors.Wrap(err, "Error configuring routes")
}

func (p ipsecProvider) delConnectivity(dst net.IPNet, destNodeAddr net.IP, isV4 bool) (err error) {
	swIfIndices, found := p.ipipIfs[destNodeAddr.String()]
	if !found {
		return errors.Errorf("Deleting unknown ipip tunnel %s", destNodeAddr.String())
	}
	e := p.s.vpp.RouteMDel(&types.MRoute{
		Dst:       &dst,
		Gw:        nil,
		SwIfIndex: swIfIndices,
	})
	if e != nil {
		err = e
		p.l.Errorf("Error deleting route ipip tunnel %v: %v", swIfIndices, err)
	}
	return errors.Wrapf(err, "Error deleting ipip tunnel route")
	// TODO remove ike profile and teardown tunnel if there are no more routes?
}
