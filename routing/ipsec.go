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
	"strings"
	"time"

	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ipsecProvider struct {
	ipipIfs map[string][]uint32
	log     *logrus.Entry
	s       *Server
}

func newIPsecProvider(s *Server) (p *ipsecProvider) {
	p = &ipsecProvider{
		ipipIfs: make(map[string][]uint32),
		log:     s.log.WithField("connectivity", "ipsec"),
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

func (p ipsecProvider) setupTunnelWithIds(i int, j int, destNodeAddr net.IP, nodeIP net.IP) (err error) {
	src := net.IP(append([]byte(nil), nodeIP.To4()...))
	src[2] += byte(i)
	dst := net.IP(append([]byte(nil), destNodeAddr.To4()...))
	dst[2] += byte(j)
	p.log.Infof("ROUTING: Adding IPsec tunnel %s -> %s", src, dst)
	swIfIndex, err := p.setupOneTunnel(src, dst, config.IPSecIkev2Psk)
	if err != nil {
		return errors.Wrapf(err, "error configuring ipsec tunnel from %s to %s", src.String(), dst.String())
	}
	p.ipipIfs[destNodeAddr.String()] = append(p.ipipIfs[destNodeAddr.String()], swIfIndex)
	return nil
}

func (p ipsecProvider) setupTunnels(destNodeAddr net.IP) (err error) {
	nodeIP := p.s.getNodeIP(vpplink.IsIP6(destNodeAddr))
	for i := 0; i < config.IpsecAddressCount; i++ {
		if config.CrossIpsecTunnels {
			for j := 0; j < config.IpsecAddressCount; j++ {
				err := p.setupTunnelWithIds(i, j, destNodeAddr, nodeIP)
				if err != nil {
					return err
				}
			}
		} else {
			err := p.setupTunnelWithIds(i, i, destNodeAddr, nodeIP)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p ipsecProvider) setupOneTunnel(src, dst net.IP, psk string) (tunSwIfIndex uint32, err error) {
	swIfIndex, err := p.s.vpp.AddIpipTunnel(src, dst, 0)
	if err != nil {
		return 0, errors.Wrapf(err, "Error adding ipip tunnel %s -> %s", src.String(), dst.String())
	}

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

	p.log.Infof("IKE: Profile %s = swifindex %d", profile, swIfIndex)
	err = p.s.vpp.SetIKEv2TunnelInterface(profile, swIfIndex)
	if err != nil {
		return 0, errors.Wrapf(err, "error configuring IPsec tunnel from %s to %s", src.String(), dst.String())
	}

	// Compare addresses lexicographically to select an initiator
	if bytes.Compare(src.To4(), dst.To4()) > 0 {
		p.log.Infof("IKE: Set responder %s->%s", src.String(), dst.String())
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
			p.log.Errorf("Cannot get IPIP tunnel %d status", ipipInterface)
			return
		}
		if !iface.IsUp {
			p.log.Debugf("IPIP tunnel %d still down", ipipInterface)
			continue
		}
		p.log.Debugf("Profile %s tunnel now up", profile)
		return
	}
}

func getIPSecRoutePaths(swIfIndices []uint32) []types.RoutePath {
	paths := make([]types.RoutePath, 0, len(swIfIndices))
	for _, swIfIndex := range swIfIndices {
		paths = append(paths, types.RoutePath{
			Gw:        nil,
			Table:     0,
			SwIfIndex: swIfIndex,
		})
	}
	return paths
}

func (p ipsecProvider) addConnectivity(cn *NodeConnectivity) (err error) {
	if _, found := p.ipipIfs[cn.NextHop.String()]; !found {
		err = p.setupTunnels(cn.NextHop)
		if err != nil {
			return errors.Wrap(err, "Error configuring IPsec tunnels")
		}
	}
	swIfIndices := p.ipipIfs[cn.NextHop.String()]
	p.log.Infof("IPSEC: ADD %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), swIfIndices)
	e := p.s.vpp.RouteAdd(&types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(swIfIndices),
	})
	if e != nil {
		err = e
		p.log.Errorf("Error setting route in VPP: %v", err)
	}
	return errors.Wrap(err, "Error configuring routes")
}

func (p ipsecProvider) delConnectivity(cn *NodeConnectivity) (err error) {
	swIfIndices, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		return errors.Errorf("Deleting unknown ipip tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("IPSEC: DEL %s via %s [%v]", cn.Dst.String(), cn.NextHop.String(), swIfIndices)
	e := p.s.vpp.RouteDel(&types.Route{
		Dst:   &cn.Dst,
		Paths: getIPSecRoutePaths(swIfIndices),
	})
	if e != nil {
		err = e
		p.log.Errorf("Error deleting route ipip tunnel %v: %v", swIfIndices, err)
	}
	return errors.Wrapf(err, "Error deleting ipip tunnel route")
	// TODO remove ike profile and teardown tunnel if there are no more routes?
}
