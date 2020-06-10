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

	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type flatL3Provider struct {
	log *logrus.Entry
	s   *Server
}

func getRoutePaths(addr net.IP) []types.RoutePath {
	return []types.RoutePath{{
		Gw:        addr,
		SwIfIndex: vpplink.AnyInterface,
		Table:     0,
	}}
}

func newFlatL3Provider(s *Server) (p *flatL3Provider) {
	p = &flatL3Provider{
		log: s.log.WithField("connectivity", "flat"),
		s:   s,
	}
	return p
}

func (p *flatL3Provider) addConnectivity(cn *NodeConnectivity) error {
	p.log.Printf("adding route %s to VPP", cn.Dst.String())
	paths := getRoutePaths(cn.NextHop)
	err := p.s.vpp.RouteAdd(&types.Route{
		Paths: paths,
		Dst:   &cn.Dst,
	})
	return errors.Wrap(err, "error replacing route")
}

func (p *flatL3Provider) delConnectivity(cn *NodeConnectivity) error {
	p.log.Debugf("removing route %s from VPP", cn.Dst.String())
	paths := getRoutePaths(cn.NextHop)
	err := p.s.vpp.RouteDel(&types.Route{
		Paths: paths,
		Dst:   &cn.Dst,
	})
	return errors.Wrap(err, "error deleting route")
}
