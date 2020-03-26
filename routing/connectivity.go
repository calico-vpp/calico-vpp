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

	"github.com/calico-vpp/calico-vpp/config"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"golang.org/x/net/context"

	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"
)

var (
	tunnelStates = make(map[string]*NodeTunnels)
)

type NodeTunnels struct {
	IpipIfs map[string]uint32
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

func (s *Server) addIpipConnectivity(dst net.IPNet, otherNodeIP net.IP, isV4 bool) error {
	if _, found := tunnelStates[s.nodeName]; !found {
		tunnelStates[s.nodeName] = &NodeTunnels{
			IpipIfs: make(map[string]uint32),
		}
	}
	tunnelState := tunnelStates[s.nodeName]
	s.l.Debugf("Adding ipip Tunnel to VPP")

	if _, found := tunnelState.IpipIfs[otherNodeIP.String()]; !found {
		nodeIp, _, err := s.getNodeIPNet()
		if err != nil {
			return errors.Wrapf(err, "Error getting node ip")
		}

		swIfIndex, err := s.vpp.AddIpipTunnel(nodeIp, otherNodeIP, isV4, 0)
		if err != nil {
			return errors.Wrapf(err, "Error adding ipip tunnel %s -> %s", nodeIp.String(), otherNodeIP.String())
		}
		err = s.vpp.InterfaceSetUnnumbered(swIfIndex, config.DataInterfaceSwIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error seting ipip tunnel unnumbered")
		}

		err = s.vpp.InterfaceAdminUp(swIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error setting ipip interface up")
		}

		err = s.vpp.AddNat44OutsideInterface(swIfIndex)
		if err != nil {
			// TODO : delete tunnel
			return errors.Wrapf(err, "Error setting ipip interface out for nat44")
		}
		tunnelState.IpipIfs[otherNodeIP.String()] = swIfIndex
	}
	swIfIndex := tunnelState.IpipIfs[otherNodeIP.String()]

	s.l.Debugf("Adding ipip tunnel route to %s via swIfIndex %d", dst.IP.String(), swIfIndex)
	return s.vpp.RouteAdd(&types.Route{
		Dst:       &dst,
		Gw:        nil,
		SwIfIndex: swIfIndex,
	})
}

func (s *Server) delIpipConnectivity(dst net.IPNet, otherNodeIP net.IP, isV4 bool) error {
	tunnelState, found := tunnelStates[s.nodeName]
	if !found {
		return errors.Errorf("Deleting ipip tunnel for unknown node %s", s.nodeName)
	}
	swIfIndex, found := tunnelState.IpipIfs[otherNodeIP.String()]
	if !found {
		return errors.Errorf("Deleting unknown ipip tunnel %s", otherNodeIP.String())
	}
	err := s.vpp.RouteDel(&types.Route{
		Dst:       &dst,
		Gw:        nil,
		SwIfIndex: swIfIndex,
	})
	if err != nil {
		return errors.Wrapf(err, "Error deleting ipip tunnel route")
	}
	delete(tunnelState.IpipIfs, otherNodeIP.String())
	return nil
}

func (s *Server) addFlatIPConnectivity(dst net.IPNet, otherNodeIP net.IP, isV4 bool) error {
	s.l.Printf("adding route %s to VPP", dst.String())
	err := s.vpp.RouteAdd(&types.Route{
		Dst:       &dst,
		Gw:        otherNodeIP,
		SwIfIndex: vpplink.AnyInterface,
	})
	return errors.Wrap(err, "error replacing route")
}

func (s *Server) delFlatIPConnectivity(dst net.IPNet, otherNodeIP net.IP, isV4 bool) error {
	s.l.Debugf("removing route %s from VPP", dst.String())
	err := s.vpp.RouteDel(&types.Route{
		Dst:       &dst,
		Gw:        otherNodeIP,
		SwIfIndex: vpplink.AnyInterface,
	})
	return errors.Wrap(err, "error deleting route")
}

func (s *Server) AddIPConnectivity(dst net.IPNet, otherNodeIP net.IP, isV4 bool, IsWithdraw bool) error {
	ipip, err := s.needIpipTunnel(dst, otherNodeIP, isV4)
	if err != nil {
		return errors.Wrapf(err, "error checking for ipip tunnel")
	}

	if ipip {
		if IsWithdraw {
			return s.delIpipConnectivity(dst, otherNodeIP, isV4)
		} else {
			return s.addIpipConnectivity(dst, otherNodeIP, isV4)
		}
	}

	if IsWithdraw {
		return s.delFlatIPConnectivity(dst, otherNodeIP, isV4)
	} else {
		return s.addFlatIPConnectivity(dst, otherNodeIP, isV4)
	}
}
