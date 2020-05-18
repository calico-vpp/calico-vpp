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
	"net"

	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ipipProvider struct {
	ipipIfs map[string]uint32
	l       *logrus.Entry
	s       *Server
}

func newIPIPProvider(s *Server) (p *ipipProvider) {
	p = &ipipProvider{
		ipipIfs: make(map[string]uint32),
		l:       s.l.WithField("connectivity", "ipip"),
		s:       s,
	}
	return p
}

func (p ipipProvider) addConnectivity(dst net.IPNet, destNodeAddr net.IP, isV4 bool) error {
	p.l.Debugf("Adding ipip Tunnel to VPP")
	if _, found := p.ipipIfs[destNodeAddr.String()]; !found {
		nodeIP, _, err := p.s.getNodeIPNet()
		if err != nil {
			return errors.Wrapf(err, "Error getting node ip")
		}
		p.l.Infof("IPIP: Add %s->%s", nodeIP.String(), dst.IP.String())

		swIfIndex, err := p.s.vpp.AddIpipTunnel(nodeIP, destNodeAddr, isV4, 0)
		if err != nil {
			return errors.Wrapf(err, "Error adding ipip tunnel %s -> %s", nodeIP.String(), destNodeAddr.String())
		}
		err = p.s.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error seting ipip tunnel unnumbered")
		}

		// Always enable GSO feature on IPIP tunnel, only a tiny negative effect on perf if GSO is not enabled on the taps
		err = p.s.vpp.EnableGSOFeature(swIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error enabling gso for ipip interface")
		}

		err = p.s.vpp.InterfaceAdminUp(swIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error setting ipip interface up")
		}

		p.s.servicesServer.AnnounceInterface(swIfIndex, true /* isTunnel */, false /* isWithdrawal */)
		p.ipipIfs[destNodeAddr.String()] = swIfIndex
		p.l.Infof("IPIP: Added ?->%s %d", dst.IP.String(), swIfIndex)
	}
	swIfIndex := p.ipipIfs[destNodeAddr.String()]
	p.l.Infof("IPIP: Added ?->%s %d", dst.IP.String(), swIfIndex)

	p.l.Debugf("Adding ipip tunnel route to %s via swIfIndex %d", dst.IP.String(), swIfIndex)
	return p.s.vpp.RouteAdd(&types.Route{
		Dst: &dst,
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nil,
		}},
	})
}

func (p ipipProvider) delConnectivity(dst net.IPNet, destNodeAddr net.IP, isV4 bool) error {
	swIfIndex, found := p.ipipIfs[destNodeAddr.String()]
	if !found {
		p.l.Infof("IPIP: Del unknown %s", destNodeAddr.String())
		return errors.Errorf("Deleting unknown ipip tunnel %s", destNodeAddr.String())
	}
	p.s.servicesServer.AnnounceInterface(swIfIndex, true /* isTunnel */, true /* isWithdrawal */)
	p.l.Infof("IPIP: Del ?->%s %d", destNodeAddr.String(), swIfIndex)
	err := p.s.vpp.RouteDel(&types.Route{
		Dst: &dst,
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting ipip tunnel route")
	}
	delete(p.ipipIfs, destNodeAddr.String())
	return nil
}
