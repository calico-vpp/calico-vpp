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

	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func getTargetPort(sPort v1.ServicePort) (int32, error) {
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

func getServicePortProto(proto v1.Protocol) types.IPProto {
	switch proto {
	case v1.ProtocolUDP:
		return types.UDP
	case v1.ProtocolSCTP:
		return types.SCTP
	case v1.ProtocolTCP:
		return types.TCP
	default:
		return types.TCP
	}
}

func formatProto(proto types.IPProto) string {
	switch proto {
	case types.UDP:
		return "UDP"
	case types.SCTP:
		return "SCTP"
	case types.TCP:
		return "TCP"
	default:
		return "???"
	}
}

func getServiceBackendIPs(servicePort *v1.ServicePort, ep *v1.Endpoints) (backendIPs []net.IP) {
	for _, set := range ep.Subsets {
		// Check if this subset exposes the port we're interested in
		for _, port := range set.Ports {
			if servicePort.Name == port.Name {
				for _, addr := range set.Addresses {
					ip := net.ParseIP(addr.IP)
					if ip != nil {
						backendIPs = append(backendIPs, ip)
					}
				}
				break
			}
		}
	}
	return backendIPs
}

func (s *Server) AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) {
	err := s.service44Provider.AnnounceLocalAddress(addr, isWithdrawal)
	if err != nil {
		s.log.Errorf("Local address %+v announcing failed : %+v", addr, err)
	}
	err = s.service66Provider.AnnounceLocalAddress(addr, isWithdrawal)
	if err != nil {
		s.log.Errorf("Local address %+v announcing failed : %+v", addr, err)
	}
}

func (s *Server) AnnounceInterface(swIfIndex uint32, isTunnel bool, isWithdrawal bool) {
	err := s.service44Provider.AnnounceInterface(swIfIndex, isTunnel, isWithdrawal)
	if err != nil {
		s.log.Errorf("Container interface %d announcing failed : %+v", swIfIndex, err)
	}
	err = s.service66Provider.AnnounceInterface(swIfIndex, isTunnel, isWithdrawal)
	if err != nil {
		s.log.Errorf("Container interface %d announcing failed : %+v", swIfIndex, err)
	}
}

func (s *Server) UpdateServiceNat(service *v1.Service, ep *v1.Endpoints) error {
	if service == nil || ep == nil {
		return errors.Errorf("nil service/endpoint, cannot process")
	}
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	if clusterIP == nil {
		s.log.Debugf("Service %s/%s has no IP, skipping", service.Namespace, service.Name)
		return nil
	}
	serviceProvider := s.service44Provider
	if vpplink.IsIP6(clusterIP) {
		serviceProvider = s.service66Provider
	}
	switch service.Spec.Type {
	case v1.ServiceTypeClusterIP:
		return serviceProvider.UpdateClusterIP(service, ep)
	case v1.ServiceTypeNodePort:
		return serviceProvider.UpdateNodePort(service, ep)
	default:
		s.log.Debugf("service type creation not supported : %s", service.Spec.Type)
		return nil
	}
}

func (s *Server) AddServiceNat(service *v1.Service, ep *v1.Endpoints) error {
	if service == nil || ep == nil {
		return errors.Errorf("nil service/endpoint, cannot process")
	}
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	if clusterIP == nil {
		s.log.Debugf("Service %s/%s has no IP, skipping", service.Namespace, service.Name)
		return nil
	}
	serviceProvider := s.service44Provider
	if vpplink.IsIP6(clusterIP) {
		serviceProvider = s.service66Provider
	}
	switch service.Spec.Type {
	case v1.ServiceTypeClusterIP:
		return serviceProvider.AddClusterIP(service, ep)
	case v1.ServiceTypeNodePort:
		return serviceProvider.AddNodePort(service, ep)
	default:
		s.log.Debugf("service type creation not supported : %s", service.Spec.Type)
		return nil
	}
}

func (s *Server) DelServiceNat(service *v1.Service, ep *v1.Endpoints) error {
	if service == nil || ep == nil {
		return errors.Errorf("nil service/endpoint, cannot process")
	}
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	if clusterIP == nil {
		s.log.Debugf("Service %s/%s has no IP, skipping", service.Namespace, service.Name)
		return nil
	}
	serviceProvider := s.service44Provider
	if vpplink.IsIP6(clusterIP) {
		serviceProvider = s.service66Provider
	}
	switch service.Spec.Type {
	case v1.ServiceTypeClusterIP:
		return serviceProvider.DelClusterIP(service, ep)
	case v1.ServiceTypeNodePort:
		return serviceProvider.DelNodePort(service, ep)
	default:
		s.log.Debugf("service type deletion not supported : %s", service.Spec.Type)
		return nil
	}
}
