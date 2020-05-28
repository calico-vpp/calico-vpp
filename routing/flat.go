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
	l *logrus.Entry
	s *Server
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
		l: s.l.WithField("connectivity", "flat"),
		s: s,
	}
	return p
}

func (p *flatL3Provider) addConnectivity(dst net.IPNet, destNodeAddr net.IP) error {
	p.l.Printf("adding route %s to VPP", dst.String())
	paths := getRoutePaths(destNodeAddr)
	err := p.s.vpp.RouteAdd(&types.Route{
		Paths: paths,
		Dst:   &dst,
	})
	return errors.Wrap(err, "error replacing route")
}

func (p *flatL3Provider) delConnectivity(dst net.IPNet, destNodeAddr net.IP) error {
	p.l.Debugf("removing route %s from VPP", dst.String())
	paths := getRoutePaths(destNodeAddr)
	err := p.s.vpp.RouteDel(&types.Route{
		Paths: paths,
		Dst:   &dst,
	})
	return errors.Wrap(err, "error deleting route")
}
