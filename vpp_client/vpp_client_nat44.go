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
	"net"
	"errors"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/vpp-calico/vpp-calico/vpp-1908-api/nat"
	"github.com/vpp-calico/vpp-calico/vpp-1908-api/ip"
)

func parseIP4Address (address string) nat.IP4Address {
	var ip nat.IP4Address
	copy(ip[:], net.ParseIP(address).To4()[0:4])
	return ip
}

func (v *VppInterface) EnableNatForwarding() (err error) {
	response := &nat.Nat44ForwardingEnableDisableReply{}
	request := &nat.Nat44ForwardingEnableDisable{
		Enable: true,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		v.log.Errorf("Nat44 enable forwarding failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func (v *VppInterface) addDelNat44Address(isAdd bool, address string) (err error) {
	response := &nat.Nat44AddDelAddressRangeReply{}
	request := &nat.Nat44AddDelAddressRange{
		FirstIPAddress:   parseIP4Address(address),
		LastIPAddress:    parseIP4Address(address),
		VrfID:            0,
		IsAdd:            isAdd,
		Flags:            nat.NAT_IS_NONE,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		v.log.Errorf("Nat44 address add failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func (v *VppInterface) AddNat44Address(address string) (err error) {
	return v.addDelNat44Address(true, address)
}

func (v *VppInterface) DelNat44Address(address string) (err error) {
	return v.addDelNat44Address(false, address)
}

func (v *VppInterface) addDelNat44Interface(isAdd bool, flags nat.NatConfigFlags, swIfIndex uint32) (err error) {
	response := &nat.Nat44InterfaceAddDelFeatureReply{}
	request := &nat.Nat44InterfaceAddDelFeature{
		IsAdd:      isAdd,
		Flags:      flags,
		SwIfIndex:  nat.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		v.log.Errorf("Nat44 addDel interface failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func (v *VppInterface) AddNat44InsideInterface(swIfIndex uint32) (err error) {
	return v.addDelNat44Interface(true, nat.NAT_IS_INSIDE, swIfIndex)
}

func (v *VppInterface) AddNat44OutsideInterface(swIfIndex uint32) (err error) {
	return v.addDelNat44Interface(true, nat.NAT_IS_OUTSIDE, swIfIndex)
}

func (v *VppInterface) DelNat44InsideInterface(swIfIndex uint32) (err error) {
	return v.addDelNat44Interface(false, nat.NAT_IS_INSIDE, swIfIndex)
}

func (v *VppInterface) DelNat44OutsideInterface(swIfIndex uint32) (err error) {
	return v.addDelNat44Interface(false, nat.NAT_IS_OUTSIDE, swIfIndex)
}

func (v *VppInterface) getServicePortProto(servicePort v1.ServicePort) (proto ip.IPProto) {
    switch servicePort.Protocol {
    	case "UDP":
    		return ip.IP_API_PROTO_UDP
    	case "SCTP":
    		return ip.IP_API_PROTO_SCTP
    	case "TCP":
    		return ip.IP_API_PROTO_TCP
    	default:
    		return ip.IP_API_PROTO_TCP
    }
}

func (v *VppInterface) getServicePortPort(servicePort v1.ServicePort) (err error, port int32) {
	switch servicePort.TargetPort.Type {
	case intstr.Int:
		return nil, servicePort.TargetPort.IntVal
	case intstr.String:
		return errors.New("Unsupported string port"), ^0
	default:
		return errors.New("Unknown port format"), ^0
	}
}
func (v *VppInterface) getLBLocalsFromServicePort(servicePort v1.ServicePort, podIPs []string) (err error, locals []nat.Nat44LbAddrPort) {
	err, port := v.getServicePortPort(servicePort)
	if err != nil {
		return err, nil
	}
	v.log.Debugf("Go mapping %d -> %d", servicePort.Port, port)
	for _, podIP := range podIPs {
		v.log.Debugf("Adding local %s:%d", podIP, port)
		locals = append(locals, nat.Nat44LbAddrPort{
        	Addr:               parseIP4Address(podIP),
        	Port:               uint16(port),
        	Probability:        uint8(10),
        })
	}
	return nil, locals
}

func (v *VppInterface) addDelNat44LBStaticMapping(isAdd bool, servicePort v1.ServicePort, externalAddr string, podIPs []string) (err error) {
	err, locals := v.getLBLocalsFromServicePort(servicePort, podIPs)
	if err != nil {
		return err
	}
	response := &nat.Nat44AddDelLbStaticMappingReply{}
	request := &nat.Nat44AddDelLbStaticMapping{
		IsAdd:              isAdd,
		Flags:              nat.NAT_IS_NONE,
		ExternalAddr:       parseIP4Address (externalAddr),
		ExternalPort:       uint16(servicePort.Port),
		Protocol:           uint8(v.getServicePortProto(servicePort)),
		Locals:             locals,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		v.log.Errorf("Nat44 add LB static failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func (v *VppInterface) AddNat44LBStaticMapping(servicePort v1.ServicePort, externalAddr string, podIPs []string) (err error) {
	return v.addDelNat44LBStaticMapping (true, servicePort, externalAddr, podIPs)
}

func (v *VppInterface) DelNat44LBStaticMapping(servicePort v1.ServicePort, externalAddr string, podIPs []string) (err error) {
	return v.addDelNat44LBStaticMapping (false, servicePort, externalAddr, podIPs)
}

