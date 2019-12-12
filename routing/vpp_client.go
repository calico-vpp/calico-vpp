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
	"fmt"
	"net"
	"sync"

	govpp "git.fd.io/govpp.git"
	vppapi "git.fd.io/govpp.git/api"
	vppcore "git.fd.io/govpp.git/core"
	vppip "github.com/vpp-calico/vpp-calico/vpp-1908-api/ip"

	"github.com/sirupsen/logrus"
)

type vppInterface struct {
	lock   sync.Mutex
	conn   *vppcore.Connection
	ch     vppapi.Channel
	socket string
	log    *logrus.Entry
}

func (v *vppInterface) replaceRoute(v4 bool, dst net.IPNet, gw net.IP) error {
	return v.doRoute(v4, dst, gw, 1)
}

func (v *vppInterface) delRoute(v4 bool, dst net.IPNet, gw net.IP) error {
	return v.doRoute(v4, dst, gw, 0)
}

func (v *vppInterface) doRoute(v4 bool, dst net.IPNet, gw net.IP, isAdd uint8) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	prefixLen, _ := dst.Mask.Size()

	route := vppip.IPRoute{
		TableID: 0,
		Paths: []vppip.FibPath{
			{
				SwIfIndex:  0xffffffff, // Is this correct?????
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

	v.log.Infof("Route add object: %+v", route)

	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil || response.Retval != 0 {
		return fmt.Errorf("Cannot add route in VPP: %v %d", err, response.Retval)
	}
	return nil
}

func newVppInterface(socket string, logger *logrus.Entry) (*vppInterface, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		logger.Errorf("cannot connect to VPP on socket %s", socket)
		return nil, fmt.Errorf("cannot connect to VPP on socket %s", socket)
	}

	// Open channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		logger.Errorf("VPP API channel creation failed")
		return nil, fmt.Errorf("channel creation failed")
	}

	return &vppInterface{
		conn:   conn,
		ch:     ch,
		socket: socket,
		log:    logger,
	}, nil
}

func (v *vppInterface) close() {
	if v.ch != nil {
		v.ch.Close()
	}
	if v.conn != nil {
		v.conn.Disconnect()
	}
}
