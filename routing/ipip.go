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
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ipipProvider struct {
	ipipIfs map[string]uint32
	log     *logrus.Entry
	s       *Server
}

func newIPIPProvider(s *Server) (p *ipipProvider) {
	p = &ipipProvider{
		ipipIfs: make(map[string]uint32),
		log:     s.log.WithField("connectivity", "ipip"),
		s:       s,
	}
	return p
}

func (p ipipProvider) addConnectivity(cn *NodeConnectivity) error {
	p.log.Debugf("Adding ipip Tunnel to VPP")
	if _, found := p.ipipIfs[cn.NextHop.String()]; !found {
		nodeIP := p.s.getNodeIP(vpplink.IsIP6(cn.NextHop))
		p.log.Infof("IPIP: Add %s->%s", nodeIP.String(), cn.Dst.IP.String())

		swIfIndex, err := p.s.vpp.AddIpipTunnel(nodeIP, cn.NextHop, 0)
		if err != nil {
			return errors.Wrapf(err, "Error adding ipip tunnel %s -> %s", nodeIP.String(), cn.NextHop.String())
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

		p.ipipIfs[cn.NextHop.String()] = swIfIndex
		p.log.Infof("IPIP: Added ?->%s %d", cn.Dst.IP.String(), swIfIndex)
	}
	swIfIndex := p.ipipIfs[cn.NextHop.String()]
	p.log.Infof("IPIP: Added ?->%s %d", cn.Dst.IP.String(), swIfIndex)

	p.log.Debugf("Adding ipip tunnel route to %s via swIfIndex %d", cn.Dst.IP.String(), swIfIndex)
	return p.s.vpp.RouteAdd(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nil,
		}},
	})
}

func (p ipipProvider) delConnectivity(cn *NodeConnectivity) error {
	swIfIndex, found := p.ipipIfs[cn.NextHop.String()]
	if !found {
		p.log.Infof("IPIP: Del unknown %s", cn.NextHop.String())
		return errors.Errorf("Deleting unknown ipip tunnel %s", cn.NextHop.String())
	}
	p.log.Infof("IPIP: Del ?->%s %d", cn.NextHop.String(), swIfIndex)
	err := p.s.vpp.RouteDel(&types.Route{
		Dst: &cn.Dst,
		Paths: []types.RoutePath{{
			SwIfIndex: swIfIndex,
			Gw:        nil,
		}},
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting ipip tunnel route")
	}
	delete(p.ipipIfs, cn.NextHop.String())
	return nil
}
