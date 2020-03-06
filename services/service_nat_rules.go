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

package services

import (
	"net"

	"github.com/calico-vpp/calico-vpp/config"
	vppip "github.com/calico-vpp/calico-vpp/vpp-1908-api/ip"
	vppnat "github.com/calico-vpp/calico-vpp/vpp-1908-api/nat"
	"github.com/calico-vpp/calico-vpp/vpp_client"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func AnnounceContainerInterface(vpp *vpp_client.VppInterface, swIfIndex uint32) error {
	// server object might not already be initialized
	err := vpp.AddNat44InsideInterface(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "Error adding nat44 inside if %d", swIfIndex)
	}
	return vpp.AddNat44OutsideInterface(swIfIndex)
}

func WithdrawContainerInterface(vpp *vpp_client.VppInterface, swIfIndex uint32) error {
	// server object might not already be initialized
	return vpp.DelNat44OutsideInterface(swIfIndex)
}

func (s *Server) getTargetPort(sPort v1.ServicePort) (int32, error) {
	tp := sPort.TargetPort
	if tp.Type == intstr.Int {
		if tp.IntVal == 0 {
			// Unset targetport
			return sPort.Port, nil
		} else {
			return tp.IntVal, nil
		}
	} else {
		return 0, errors.Errorf("Unsupported string type for service port: %+v", sPort)
	}
}

func (s *Server) getServicePortProto(proto v1.Protocol) vppip.IPProto {
	switch proto {
	case v1.ProtocolUDP:
		return vppip.IP_API_PROTO_UDP
	case v1.ProtocolSCTP:
		return vppip.IP_API_PROTO_SCTP
	case v1.ProtocolTCP:
		return vppip.IP_API_PROTO_TCP
	default:
		return vppip.IP_API_PROTO_TCP
	}
}

func (s *Server) getServiceBackendIPs(servicePort *v1.ServicePort, ep *v1.Endpoints) []string {
	var backendIPs []string
	for _, set := range ep.Subsets {
		// Check if this subset exposes the port we're interested in
		for _, port := range set.Ports {
			if servicePort.Name == port.Name {
				for _, addr := range set.Addresses {
					backendIPs = append(backendIPs, addr.IP)
				}
				break
			}
		}
	}
	return backendIPs
}

func (s *Server) addNat44NodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	err = s.vpp.AddNat44Address(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error adding nat44 address")
	}
	err = s.vpp.AddNat44OutsideInterface(config.DataInterfaceSwIfIndex)
	if err != nil {
		s.log.Errorf("Error adding nat44 physical interface")
		// return errors.Wrap(err, "Error adding nat44 physical interface")
	}
	err = s.vpp.AddNat44InterfaceAddress(config.DataInterfaceSwIfIndex, vppnat.NAT_IS_TWICE_NAT)
	if err != nil {
		s.log.Errorf("Error adding nat44 physical interface address")
		// return errors.Wrap(err, "Error adding nat44 physical interface address")
	}
	nodeIp, _, err := s.getNodeIP()
	if err != nil {
		return errors.Wrap(err, "Error getting Node IP")
	}
	for _, servicePort := range service.Spec.Ports {
		backendIPs := s.getServiceBackendIPs(&servicePort, ep)
		s.log.Debugf("%d backends found for service %s/%s port %s",
			len(backendIPs), service.Namespace, service.Name, servicePort.Name)
		if len(backendIPs) == 0 {
			continue
		}
		targetPort, err := s.getTargetPort(servicePort)
		if err != nil {
			s.log.Warnf("Error determinig target port: %v", err)
			continue
		}
		err = s.vpp.AddNat44LB(nodeIp.String(), s.getServicePortProto(servicePort.Protocol),
			servicePort.Port, backendIPs, targetPort)
		if err != nil {
			return errors.Wrapf(err, "Error adding local NAT44 LB rule for NodePort")
		}
		err = s.vpp.AddNat44LB(service.Spec.ClusterIP, s.getServicePortProto(servicePort.Protocol),
			servicePort.NodePort, backendIPs, targetPort)
		if err != nil {
			return errors.Wrapf(err, "Error adding external NAT44 LB rule for NodePort")
		}
	}
	return nil
}

func (s *Server) delNat44NodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	nodeIp, _, err := s.getNodeIP()
	if err != nil {
		return errors.Wrap(err, "Error getting Node IP")
	}
	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := s.getServiceBackendIPs(&servicePort, ep)
		if len(backendIPs) == 0 {
			continue
		}
		err = s.vpp.DelNat44LB(nodeIp.String(), s.getServicePortProto(servicePort.Protocol),
			servicePort.Port, len(backendIPs))
		if err != nil {
			return errors.Wrap(err, "Error deleting local NAT44 LB rule for NodePort")
		}

		err = s.vpp.DelNat44LB(service.Spec.ClusterIP, s.getServicePortProto(servicePort.Protocol),
			servicePort.NodePort, len(backendIPs))
		if err != nil {
			return errors.Wrapf(err, "Error deleting external NAT44 LB rule for NodePort")
		}
	}

	err = s.vpp.DelNat44Address(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error deleting nat44 address")
	}
	return nil
}

func (s *Server) addNat44ClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	err = s.vpp.AddNat44Address(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error adding nat44 address")
	}
	err = s.vpp.AddNat44OutsideInterface(config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "Error adding nat44 physical interface")
	}

	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := s.getServiceBackendIPs(&servicePort, ep)
		s.log.Debugf("%d backends found for service %s/%s port %s", len(backendIPs),
			service.Namespace, service.Name, servicePort.Name)
		if len(backendIPs) == 0 {
			continue
		}
		targetPort, err := s.getTargetPort(servicePort)
		if err != nil {
			s.log.Warnf("Error determinig target port: %v", err)
			continue
		}
		err = s.vpp.AddNat44LB(service.Spec.ClusterIP, s.getServicePortProto(servicePort.Protocol),
			servicePort.Port, backendIPs, targetPort)
		if err != nil {
			return errors.Wrap(err, "Error adding nat44 lb config")
		}
	}
	return nil
}

func (s *Server) delNat44ClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := s.getServiceBackendIPs(&servicePort, ep)

		s.log.Debugf("%d backends found for service %s/%s port %s", len(backendIPs),
			service.Namespace, service.Name, servicePort.Name)
		if len(backendIPs) == 0 {
			continue
		}
		err = s.vpp.DelNat44LB(service.Spec.ClusterIP, s.getServicePortProto(servicePort.Protocol),
			servicePort.Port, len(backendIPs))
		if err != nil {
			return errors.Wrap(err, "Error deleting nat44 lb config")
		}
	}

	err = s.vpp.DelNat44Address(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error deleting nat44 address")
	}
	return nil
}

func (s *Server) AddServiceNat(service *v1.Service, ep *v1.Endpoints) error {
	if service == nil || ep == nil {
		return errors.Errorf("nil service/endpoint, cannot process")
	}
	if net.ParseIP(service.Spec.ClusterIP) == nil {
		s.log.Debugf("Service %s/%s has no IP, skipping", service.Namespace, service.Name)
		return nil
	}

	switch service.Spec.Type {
	case v1.ServiceTypeClusterIP:
		return s.addNat44ClusterIP(service, ep)
	case v1.ServiceTypeNodePort:
		return s.addNat44NodePort(service, ep)
	default:
		s.log.Debugf("service type creation not supported : %s", service.Spec.Type)
		return nil
	}
}

func (s *Server) DelServiceNat(service *v1.Service, ep *v1.Endpoints) error {
	if service == nil || ep == nil {
		return errors.Errorf("nil service/endpoint, cannot process")
	}

	switch service.Spec.Type {
	case v1.ServiceTypeClusterIP:
		return s.delNat44ClusterIP(service, ep)
	case v1.ServiceTypeNodePort:
		return s.delNat44NodePort(service, ep)
	default:
		s.log.Debugf("service type deletion not supported : %s", service.Spec.Type)
		return nil
	}
}
