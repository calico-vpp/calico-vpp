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

package vpp_client

import (
	"fmt"
	"net"

	vppip "github.com/vpp-calico/vpp-calico/vpp-1908-api/ip"
	"github.com/pkg/errors"
)

func (v *VppInterface) GetRoutes(tableID uint32, isIPv6 uint8) (err error, routes []vppip.IPRoute) {
	request := &vppip.IPRouteDump{
		Table: vppip.IPTable{
			TableID: tableID,
			IsIP6:   isIPv6,
		},
	}
	response := &vppip.IPRouteDetails{}
	stream := v.ch.SendMultiRequest(request)
	for {
		stop, err := stream.ReceiveReply(response)
		if err != nil {
			v.log.Errorf("error listing VPP routes: %v", err)
			return err, nil
		}
		if stop {
			return nil, routes
		}
		routes = append(routes, response.Route)
	}
}

func (v *VppInterface) addDelNeighbor(neighbor vppip.IPNeighbor, isAdd uint8) error {
	request := &vppip.IPNeighborAddDel{
		IsAdd:    isAdd,
		Neighbor: neighbor,
	}
	response := &vppip.IPNeighborAddDelReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "failed to delete neighbor from VPP")
	}
	v.log.Debugf("deleted neighbor %+v", neighbor)
	return nil
}

func (v *VppInterface) AddNeighbor(neighbor vppip.IPNeighbor) error {
	return v.addDelNeighbor(neighbor, 1)
}

func (v *VppInterface) DelNeighbor(neighbor vppip.IPNeighbor) error {
	return v.addDelNeighbor(neighbor, 0)
}

func (v *VppInterface) addDelIPRoute(route vppip.IPRoute, isAdd uint8) {
	request := &vppip.IPRouteAddDel{
		IsAdd:    isAdd,
		Route:    route,
	}
	response := &vppip.IPRouteAddDelReply{}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		v.log.Warnf("failed to delete neighbor from VPP")
	}
	v.log.Debugf("deleted route %+v", route)
}

func (v *VppInterface) AddIPRoute(neighbor vppip.IPRoute) {
	v.addDelIPRoute(neighbor, 1)
}

func (v *VppInterface) DelIPRoute(neighbor vppip.IPRoute) {
	v.addDelIPRoute(neighbor, 0)
}

func (v *VppInterface) ReplaceRoute(v4 bool, dst net.IPNet, gw net.IP, swIfIndex uint32) error {
	return v.addDelRoute(v4, dst, gw, swIfIndex, 1)
}

func (v *VppInterface) DelRoute(v4 bool, dst net.IPNet, gw net.IP, swIfIndex uint32) error {
	return v.addDelRoute(v4, dst, gw, swIfIndex, 0)
}

func (v *VppInterface) addDelRoute(v4 bool, dst net.IPNet, gw net.IP, swIfIndex uint32, isAdd uint8) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	prefixLen, _ := dst.Mask.Size()

	route := vppip.IPRoute{
		TableID: 0,
		Paths: []vppip.FibPath{
			{
				SwIfIndex:  swIfIndex, // 0xffffffff, // Is this correct?????
				TableID:    0,
				RpfID:      0,
				Weight:     1,
				Preference: 0,
				Type:       vppip.FIB_API_PATH_TYPE_NORMAL,
				Flags:      vppip.FIB_API_PATH_FLAG_NONE,
			},
		},
	}
	if v4 {
		ip := [4]uint8{}
		copy(ip[:], dst.IP.To4())
		route.Prefix = vppip.Prefix{
			Address: vppip.Address{
				Af: vppip.ADDRESS_IP4,
				Un: vppip.AddressUnionIP4(ip),
			},
			Len: uint8(prefixLen),
		}
		copy(ip[:], gw.To4())
		route.Paths[0].Proto = vppip.FIB_API_PATH_NH_PROTO_IP4
		route.Paths[0].Nh.Address = vppip.AddressUnionIP4(ip)
	} else {
		ip := [16]uint8{}
		copy(ip[:], dst.IP.To16())
		route.Prefix = vppip.Prefix{
			Address: vppip.Address{
				Af: vppip.ADDRESS_IP6,
				Un: vppip.AddressUnionIP6(ip),
			},
			Len: uint8(prefixLen),
		}
		copy(ip[:], gw.To16())
		route.Paths[0].Proto = vppip.FIB_API_PATH_NH_PROTO_IP6
		route.Paths[0].Nh.Address = vppip.AddressUnionIP6(ip)
	}

	request := &vppip.IPRouteAddDel{
		IsAdd:       isAdd,
		IsMultipath: 0,
		Route:       route,
	}

	response := &vppip.IPRouteAddDelReply{}

	v.log.Debugf("Route add object: %+v", route)

	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("Cannot add route in VPP: %v %d", err, response.Retval)
	}
	return nil
}


