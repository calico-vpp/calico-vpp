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

	"github.com/calico-vpp/calico-vpp/vpp-1908-api/ipip"
	"github.com/pkg/errors"
)

func ipipAddressFromNetIP(addr net.IP, isV4 bool) ipip.Address {
	var ip ipip.AddressUnion = ipip.AddressUnion{}
	if isV4 {
		var ip4 ipip.IP4Address
		copy(ip4[:], addr.To4()[0:4])
		ip.SetIP4(ip4)
		return ipip.Address{
			Af: ipip.ADDRESS_IP4,
			Un: ip,
		}
	} else {
		var ip6 ipip.IP6Address
		copy(ip6[:], addr.To16())
		ip.SetIP6(ip6)
		return ipip.Address{
			Af: ipip.ADDRESS_IP6,
			Un: ip,
		}
	}
}

func (v *VppInterface) AddIpipTunnel(src net.IP, dst net.IP, isV4 bool, tableID uint32) (SwIfIndex uint32, err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ipip.IpipAddTunnelReply{}
	request := &ipip.IpipAddTunnel{
		Tunnel: ipip.IpipTunnel{
			Instance: ^uint32(0),
			Src:      ipipAddressFromNetIP(src.To4(), isV4),
			Dst:      ipipAddressFromNetIP(dst.To4(), isV4),
			TableID:  0,
		},
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return ^uint32(1), errors.Wrap(err, "Add IPIP Tunnel failed")
	} else if response.Retval != 0 {
		return ^uint32(1), fmt.Errorf("Add IPIP Tunnel failed with retval %d", response.Retval)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *VppInterface) DelIpipTunnel(swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ipip.IpipDelTunnelReply{}
	request := &ipip.IpipDelTunnel{
		SwIfIndex: ipip.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Del IPIP Tunnel %d failed", swIfIndex)
	} else if response.Retval != 0 {
		return fmt.Errorf("Del IPIP Tunnel %d failed with retval %d", swIfIndex, response.Retval)
	}
	return nil
}
