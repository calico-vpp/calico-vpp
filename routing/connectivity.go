// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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
	"fmt"
	"net"
	"os"

	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"golang.org/x/net/context"
)

type connectivityProvider interface {
	addConnectivity(dst net.IPNet, destNode net.IP, isV4 bool) error
	delConnectivity(dst net.IPNet, destNode net.IP, isV4 bool) error
}

func (s *Server) getNodeIPNet() (ip net.IP, ipNet *net.IPNet, err error) {
	// TODO cache, we only do this to get the address subnet
	node, err := s.clientv3.Nodes().Get(context.Background(), s.nodeName, options.GetOptions{})
	if err != nil {
		return nil, nil, errors.Wrap(err, "error getting node config")
	}
	ip, ipNet, err = net.ParseCIDR(node.Spec.BGP.IPv4Address)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error parsing node IPv4 network: %s", node.Spec.BGP.IPv4Address)
	}
	return ip, ipNet, nil
}

func (s *Server) needIpipTunnel(dst net.IPNet, otherNodeIP net.IP, isV4 bool) (ipip bool, err error) {
	ipPool := s.ipam.match(dst)
	if ipPool == nil {
		return false, nil
	}
	if ipPool.Spec.IPIPMode == calicov3.IPIPModeNever {
		return false, nil
	}
	_, ipNet, err := s.getNodeIPNet()
	if err != nil {
		return false, errors.Wrapf(err, "error getting node ip")
	}

	if ipPool.Spec.IPIPMode == calicov3.IPIPModeCrossSubnet && !isCrossSubnet(otherNodeIP, *ipNet) {
		return false, nil
	}
	if !isV4 {
		return false, fmt.Errorf("ipv6 not supported for ipip")
	}

	return true, nil
}

func (s *Server) updateIPConnectivity(dst net.IPNet, otherNodeIP net.IP, isV4 bool, IsWithdraw bool) error {
	var provider connectivityProvider = s.flat

	ipip, err := s.needIpipTunnel(dst, otherNodeIP, isV4)
	if err != nil {
		return errors.Wrapf(err, "error checking for ipip tunnel")
	}
	if ipip && os.Getenv("CALICOVPP_IPSEC_ENABLED") != "" {
		provider = s.ipsec
	} else if ipip {
		provider = s.ipip
	}

	if IsWithdraw {
		return provider.delConnectivity(dst, otherNodeIP, isV4)
	} else {
		return provider.addConnectivity(dst, otherNodeIP, isV4)
	}
}
