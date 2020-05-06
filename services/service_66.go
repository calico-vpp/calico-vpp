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

	// "github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/vpplink"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type Service66Provider struct {
	log *logrus.Entry
	vpp *vpplink.VppLink
	s   *Server
}

func newService66Provider(s *Server) (p *Service66Provider) {
	p = &Service66Provider{
		log: s.log.WithField("service", "nat66"),
		vpp: s.vpp,
		s:   s,
	}
	return p
}

func getMaxCIDRLen(isv6 bool) int {
	if isv6 {
		return 128
	} else {
		return 32
	}
}

func getMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := getMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func getClusterIPNet(service *v1.Service) (*net.IPNet, error) {
	addr := net.ParseIP(service.Spec.ClusterIP)
	if addr == nil {
		return nil, errors.Errorf("Unable to parse IP %s", service.Spec.ClusterIP)
	}
	return &net.IPNet{
		Mask: getMaxCIDRMask(addr),
		IP:   addr,
	}, nil
}

func (p *Service66Provider) Init() error {
	return nil /* TODO */
}

func (p *Service66Provider) AnnounceContainerInterface(swIfIndex uint32, isWithdrawal bool) error {
	if isWithdrawal {
		return p.vpp.CalicoDelInterfaceNat6(swIfIndex)
	}
	return p.vpp.CalicoAddInterfaceNat6(swIfIndex)
}

func (p *Service66Provider) AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) error {
	return nil /* TODO : sourceNAT if needed */
}

func (p *Service66Provider) UpdateNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	// TODO
	return nil
}

func (p *Service66Provider) UpdateClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	// TODO
	return nil
}

func (p *Service66Provider) AddNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	clusterIPNet, err := getClusterIPNet(service)
	if err != nil {
		return errors.Wrapf(err, "Add clusterIP parse error")
	}
	_, nodeIPNet, err := p.s.getNodeIP()
	if err != nil {
		return errors.Wrap(err, "Error getting Node IP")
	}
	for _, servicePort := range service.Spec.Ports {
		targetPort, err := getTargetPort(servicePort)
		if err != nil {
			p.log.Warnf("Error determinig target port: %v", err)
			continue
		}
		proto := getServicePortProto(servicePort.Protocol)
		err = p.vpp.CalicoAddVip(nodeIPNet, servicePort.Port, targetPort, true /* encapIsv6 */, proto)
		if err != nil {
			p.log.Errorf("Error Adding VIP %s %d->%d", nodeIPNet, servicePort.Port, targetPort)
		}
		err = p.vpp.CalicoAddVip(clusterIPNet, servicePort.Port, targetPort, true /* encapIsv6 */, proto)
		if err != nil {
			p.log.Errorf("Error Adding VIP %s %d->%d", clusterIPNet, servicePort.Port, targetPort)
		}
	}

	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := getServiceBackendIPs(&servicePort, ep)
		p.log.Debugf("%d backends found for service %s/%s port %s", len(backendIPs),
			service.Namespace, service.Name, servicePort.Name)
		proto := getServicePortProto(servicePort.Protocol)
		for _, backendIP := range backendIPs {
			err = p.vpp.CalicoAddAs(backendIP, nodeIPNet, servicePort.Port, proto)
			if err != nil {
				return errors.Wrapf(err, "Error adding AS %+v %+v:%d", backendIP.String(), nodeIPNet, servicePort.Port)
			}
			err = p.vpp.CalicoAddAs(backendIP, clusterIPNet, servicePort.NodePort, proto)
			if err != nil {
				return errors.Wrapf(err, "Error adding AS %+v %+v:%d", backendIP.String(), clusterIPNet, servicePort.NodePort)
			}
		}
	}
	return nil
}

func (p *Service66Provider) DelNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil // TODO
}

func (p *Service66Provider) AddClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	clusterIPNet, err := getClusterIPNet(service)
	if err != nil {
		return errors.Wrapf(err, "Add clusterIP parse error")
	}
	for _, servicePort := range service.Spec.Ports {
		targetPort, err := getTargetPort(servicePort)
		if err != nil {
			p.log.Warnf("Error determinig target port: %v", err)
			continue
		}
		proto := getServicePortProto(servicePort.Protocol)
		err = p.vpp.CalicoAddVip(clusterIPNet, servicePort.Port, targetPort, true /* encapIsv6 */, proto)
		if err != nil {
			p.log.Errorf("Error Adding VIP %s %d->%d", clusterIPNet, servicePort.Port, targetPort)
		}
	}

	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := getServiceBackendIPs(&servicePort, ep)
		p.log.Debugf("%d backends found for service %s/%s port %s", len(backendIPs),
			service.Namespace, service.Name, servicePort.Name)
		for _, backendIP := range backendIPs {
			proto := getServicePortProto(servicePort.Protocol)
			err = p.vpp.CalicoAddAs(backendIP, clusterIPNet, servicePort.Port, proto)
			if err != nil {
				return errors.Wrapf(err, "Error adding AS %+v %+v:%d", backendIP.String(), clusterIPNet, servicePort.Port)
			}
		}
	}
	return nil
}

func (p *Service66Provider) DelClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	clusterIPNet, err := getClusterIPNet(service)
	if err != nil {
		return errors.Wrapf(err, "Add clusterIP parse error")
	}

	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := getServiceBackendIPs(&servicePort, ep)
		p.log.Debugf("%d backends found for service %s/%s port %s", len(backendIPs),
			service.Namespace, service.Name, servicePort.Name)
		for _, backendIP := range backendIPs {
			proto := getServicePortProto(servicePort.Protocol)
			err = p.vpp.CalicoDelAs(backendIP, clusterIPNet, servicePort.Port, proto)
			if err != nil {
				return errors.Wrapf(err, "Error deleting AS %+v %+v:%d", backendIP.String(), clusterIPNet, servicePort.Port)
			}
		}
	}

	for _, servicePort := range service.Spec.Ports {
		targetPort, err := getTargetPort(servicePort)
		if err != nil {
			p.log.Warnf("Error determinig target port: %v", err)
			continue
		}
		proto := getServicePortProto(servicePort.Protocol)
		err = p.vpp.CalicoDelVip(clusterIPNet, servicePort.Port, targetPort, true /* encapIsv6 */, proto)
		if err != nil {
			p.log.Errorf("Error Deleting VIP %s %d->%d", clusterIPNet, servicePort.Port, targetPort)
		}
	}

	return nil
}
