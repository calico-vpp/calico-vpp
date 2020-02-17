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

	"github.com/pkg/errors"
	"github.com/calico-vpp/calico-vpp/vpp-1908-api/ip"
	"github.com/calico-vpp/calico-vpp/vpp-1908-api/nat"
)

func parseIP4Address(address string) nat.IP4Address {
	var ip nat.IP4Address
	copy(ip[:], net.ParseIP(address).To4()[0:4])
	return ip
}

func (v *VppInterface) EnableNatForwarding() (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44ForwardingEnableDisableReply{}
	request := &nat.Nat44ForwardingEnableDisable{
		Enable: true,
	}
	v.log.Debug("Enabling NAT44 forwarding")
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "NAT44 forwarding enable failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("NAT44 forwarding enable failed with retval: %d", response.Retval)
	}
	return nil
}

func (v *VppInterface) addDelNat44Address(isAdd bool, address string) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44AddDelAddressRangeReply{}
	request := &nat.Nat44AddDelAddressRange{
		FirstIPAddress: parseIP4Address(address),
		LastIPAddress:  parseIP4Address(address),
		VrfID:          0,
		IsAdd:          isAdd,
		Flags:          nat.NAT_IS_NONE,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 address add failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 address add failed with retval %d", response.Retval)
	}
	return nil
}

func (v *VppInterface) AddNat44Address(address string) error {
	return v.addDelNat44Address(true, address)
}

func (v *VppInterface) DelNat44Address(address string) error {
	return v.addDelNat44Address(false, address)
}

func (v *VppInterface) addDelNat44Interface(isAdd bool, flags nat.NatConfigFlags, swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44InterfaceAddDelFeatureReply{}
	request := &nat.Nat44InterfaceAddDelFeature{
		IsAdd:     isAdd,
		Flags:     flags,
		SwIfIndex: nat.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 addDel interface failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 addDel interface failed: %d", response.Retval)
	}
	return nil
}

func (v *VppInterface) AddNat44InsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(true, nat.NAT_IS_INSIDE, swIfIndex)
}

func (v *VppInterface) AddNat44OutsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(true, nat.NAT_IS_OUTSIDE, swIfIndex)
}

func (v *VppInterface) DelNat44InsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(false, nat.NAT_IS_INSIDE, swIfIndex)
}

func (v *VppInterface) DelNat44OutsideInterface(swIfIndex uint32) error {
	return v.addDelNat44Interface(false, nat.NAT_IS_OUTSIDE, swIfIndex)
}

func (v *VppInterface) getLBLocals(backends []string, port int32) (locals []nat.Nat44LbAddrPort) {
	for _, ip := range backends {
		v.log.Debugf("Adding local %s:%d", ip, port)
		locals = append(locals, nat.Nat44LbAddrPort{
			Addr:        parseIP4Address(ip),
			Port:        uint16(port),
			Probability: uint8(10),
		})
	}
	return locals
}

func (v *VppInterface) addDelNat44LBStaticMapping(
	isAdd bool,
	extAddr string,
	proto ip.IPProto,
	extPort int32,
	backends []string,
	backendPort int32,
) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	locals := v.getLBLocals(backends, backendPort)
	response := &nat.Nat44AddDelLbStaticMappingReply{}
	request := &nat.Nat44AddDelLbStaticMapping{
		IsAdd:        isAdd,
		Flags:        nat.NAT_IS_NONE,
		ExternalAddr: parseIP4Address(extAddr),
		ExternalPort: uint16(extPort),
		Protocol:     uint8(proto),
		Locals:       locals,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 add LB static failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 add LB static failed: %d", response.Retval)
	}
	return nil
}

func (v *VppInterface) AddNat44LBStaticMapping(
	externalAddr string,
	serviceProto ip.IPProto,
	externalPort int32,
	backendIPs []string,
	backendPort int32,
) error {
	return v.addDelNat44LBStaticMapping(true, externalAddr, serviceProto, externalPort, backendIPs, backendPort)
}

func (v *VppInterface) DelNat44LBStaticMapping(
	externalAddr string,
	serviceProto ip.IPProto,
	externalPort int32,
) error {
	return v.addDelNat44LBStaticMapping(false, externalAddr, serviceProto, externalPort, []string{}, 0)
}

func (v *VppInterface) addDelNat44StaticMapping(
	isAdd bool,
	externalAddr string,
	serviceProto ip.IPProto,
	externalPort int32,
	backendIP string,
	backendPort int32,
) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &nat.Nat44AddDelStaticMappingReply{}
	request := &nat.Nat44AddDelStaticMapping{
		IsAdd:             isAdd,
		Flags:             nat.NAT_IS_NONE,
		LocalIPAddress:    parseIP4Address(backendIP),
		ExternalIPAddress: parseIP4Address(externalAddr),
		Protocol:          uint8(serviceProto),
		LocalPort:         uint16(backendPort),
		ExternalPort:      uint16(externalPort),
		ExternalSwIfIndex: 0xffffffff,
	}
	err := v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "Nat44 static mapping failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("Nat44 add LB static failed: %d", response.Retval)
	}
	return nil
}

func (v *VppInterface) AddNat44StaticMapping(
	externalAddr string,
	serviceProto ip.IPProto,
	externalPort int32,
	backendIP string,
	backendPort int32,
) error {
	return v.addDelNat44StaticMapping(true, externalAddr, serviceProto, externalPort, backendIP, backendPort)
}

func (v *VppInterface) DelNat44StaticMapping(
	externalAddr string,
	serviceProto ip.IPProto,
	externalPort int32,
) error {
	return v.addDelNat44StaticMapping(false, externalAddr, serviceProto, externalPort, "0.0.0.0", 0)
}

func (v *VppInterface) AddNat44LB(
	serviceIP string,
	serviceProto ip.IPProto,
	servicePort int32,
	backendIPs []string,
	backendPort int32,
) error {
	if len(backendIPs) == 0 {
		return fmt.Errorf("No backends provided for NAT44")
	}
	if len(backendIPs) == 1 {
		return v.AddNat44StaticMapping(serviceIP, serviceProto, servicePort, backendIPs[0], backendPort)
	}
	return v.AddNat44LBStaticMapping(serviceIP, serviceProto, servicePort, backendIPs, backendPort)
}

func (v *VppInterface) DelNat44LB(
	serviceIP string,
	serviceProto ip.IPProto,
	servicePort int32,
	backendCount int,
) error {
	if backendCount == 0 {
		return fmt.Errorf("No backends provided for NAT44")
	}
	if backendCount == 1 {
		return v.DelNat44StaticMapping(serviceIP, serviceProto, servicePort)
	}
	return v.DelNat44LBStaticMapping(serviceIP, serviceProto, servicePort)
}
