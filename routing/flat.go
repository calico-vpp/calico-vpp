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
	"os"
	"strconv"

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
	extraAddressCount, _ := strconv.ParseInt(os.Getenv("CALICOVPP_IPSEC_ASSUME_EXTRA_ADDRESSES"), 10, 8)
	extraAddressIncrement, _ := strconv.ParseInt(os.Getenv("CALICOVPP_IPSEC_EXTRA_ADDRESSES_INCREMENT"), 10, 8)
	paths := make([]types.RoutePath, extraAddressCount+1)
	paths = append(paths, types.RoutePath{
		Gw:        addr,
		SwIfIndex: vpplink.AnyInterface,
		Table:     0,
	})

	for i := int64(0); i < 1+extraAddressCount; i++ {
		naddr := net.IP(append([]byte(nil), addr.To4()...))
		naddr[2] += byte(i * extraAddressIncrement)
		paths = append(paths, types.RoutePath{
			SwIfIndex: vpplink.AnyInterface,
			Gw:        naddr,
			Table:     0,
		})
	}
	return paths
}

func newFlatL3Provider(s *Server) (p *flatL3Provider) {
	p = &flatL3Provider{
		l: s.l.WithField("connectivity", "flat"),
		s: s,
	}
	return p
}

func (p *flatL3Provider) addConnectivity(dst net.IPNet, destNodeAddr net.IP, isV4 bool) error {
	p.l.Printf("adding route %s to VPP", dst.String())
	paths := getRoutePaths(destNodeAddr)
	err := p.s.vpp.RouteAdd(&types.Route{
		Paths: paths,
		Dst:   &dst,
	})
	return errors.Wrap(err, "error replacing route")
}

func (p *flatL3Provider) delConnectivity(dst net.IPNet, destNodeAddr net.IP, isV4 bool) error {
	p.l.Debugf("removing route %s from VPP", dst.String())
	paths := getRoutePaths(destNodeAddr)
	err := p.s.vpp.RouteDel(&types.Route{
		Paths: paths,
		Dst:   &dst,
	})
	return errors.Wrap(err, "error deleting route")
}
