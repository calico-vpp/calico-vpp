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
	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type Service44Provider struct {
	log                *logrus.Entry
	vpp                *vpplink.VppLink
	s                  *Server
	nat44addressRefCnt map[string]int
}

func newService44Provider(s *Server) (p *Service44Provider) {
	p = &Service44Provider{
		log: s.log.WithField("service", "nat44"),
		vpp: s.vpp,
		s:   s,
	}
	return p
}

func (p *Service44Provider) Init() (err error) {
	p.nat44addressRefCnt = make(map[string]int)
	err = p.vpp.AddNat44OutsideInterface(config.DataInterfaceSwIfIndex)
	if err != nil {
		p.log.Errorf("Error set nat44 out PHY  %+v", err)
	}
	err = p.vpp.AddNat44InterfaceAddress(config.DataInterfaceSwIfIndex, types.NatTwice)
	if err != nil {
		p.log.Errorf("Error set nat44 in twice-nat PHY %+v", err)
	}
	err = p.vpp.AddNat44OutsideInterface(p.s.vppTapSwIfindex)
	if err != nil {
		p.log.Errorf("Error set nat44 out vpptap0 %+v", err)
	}
	err = p.vpp.AddNat44InsideInterface(p.s.vppTapSwIfindex)
	if err != nil {
		p.log.Errorf("Error set nat44 in vpptap0 %+v", err)
	}
	return nil
}

func (p *Service44Provider) AnnounceContainerInterface(swIfIndex uint32, isWithdrawal bool) error {
	if isWithdrawal {
		return p.vpp.DelNat44OutsideInterface(swIfIndex)
	}
	// server object might not already be initialized
	err := p.vpp.AddNat44InsideInterface(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "Error adding nat44 inside if %d", swIfIndex)
	}
	return p.vpp.AddNat44OutsideInterface(swIfIndex)
}

func (p *Service44Provider) AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) error {
	return nil /* Nothing to do */
}

func (p *Service44Provider) addNATAddress(addr string) error {
	if refCnt, ok := p.nat44addressRefCnt[addr]; ok {
		p.nat44addressRefCnt[addr] = refCnt + 1
	} else {
		p.nat44addressRefCnt[addr] = 1
		return p.vpp.AddNat44Address(addr)
	}
	return nil
}

func (p *Service44Provider) delNATAddress(addr string) error {
	if refCnt, ok := p.nat44addressRefCnt[addr]; ok {
		if refCnt > 1 {
			p.nat44addressRefCnt[addr] = refCnt - 1
		} else if refCnt == 1 {
			delete(p.nat44addressRefCnt, addr)
			return p.vpp.DelNat44Address(addr)
		} else {
			p.log.Errorf("Wrong refCnt : %d", refCnt)
		}
	} else {
		p.log.Errorf("Address wasn't added : %s", addr)
	}
	return nil
}

func (p *Service44Provider) AddNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	err = p.addNATAddress(service.Spec.ClusterIP)
	if err != nil {
		p.log.Errorf("Error adding nat44 Nodeport address %s %+v", service.Spec.ClusterIP, err)
	}
	nodeIp, _, err := p.s.getNodeIP()
	if err != nil {
		return errors.Wrap(err, "Error getting Node IP")
	}

	for _, servicePort := range service.Spec.Ports {
		backendIPs := getServiceBackendIPs(&servicePort, ep)
		p.log.Debugf("%d backends found for service %s/%s port %s",
			len(backendIPs), service.Namespace, service.Name, servicePort.Name)
		if len(backendIPs) == 0 {
			continue
		}
		targetPort, err := getTargetPort(servicePort)
		if err != nil {
			p.log.Warnf("Error determinig target port: %v", err)
			continue
		}
		err = p.vpp.AddNat44LB(nodeIp.String(), getServicePortProto(servicePort.Protocol),
			servicePort.Port, backendIPs, targetPort)
		if err != nil {
			return errors.Wrapf(err, "Error adding local NAT44 LB rule for NodePort %s", nodeIp.String())
		}
		err = p.vpp.AddNat44LB(service.Spec.ClusterIP, getServicePortProto(servicePort.Protocol),
			servicePort.NodePort, backendIPs, targetPort)
		if err != nil {
			return errors.Wrapf(err, "Error adding external NAT44 LB rule for NodePort %s", service.Spec.ClusterIP)
		}
	}
	return nil
}

func (p *Service44Provider) DelNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	nodeIp, _, err := p.s.getNodeIP()
	if err != nil {
		return errors.Wrap(err, "Error getting Node IP")
	}
	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := getServiceBackendIPs(&servicePort, ep)
		if len(backendIPs) == 0 {
			continue
		}
		err = p.vpp.DelNat44LB(nodeIp.String(), getServicePortProto(servicePort.Protocol),
			servicePort.Port, len(backendIPs))
		if err != nil {
			return errors.Wrap(err, "Error deleting local NAT44 LB rule for NodePort")
		}

		err = p.vpp.DelNat44LB(service.Spec.ClusterIP, getServicePortProto(servicePort.Protocol),
			servicePort.NodePort, len(backendIPs))
		if err != nil {
			return errors.Wrapf(err, "Error deleting external NAT44 LB rule for NodePort")
		}
	}

	err = p.delNATAddress(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error deleting nat44 address")
	}
	return nil
}

func (p *Service44Provider) AddClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	err = p.addNATAddress(service.Spec.ClusterIP)
	if err != nil {
		p.log.Errorf("Error adding nat44 address %s %+v", service.Spec.ClusterIP, err)
	}
	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := getServiceBackendIPs(&servicePort, ep)
		p.log.Debugf("%d backends found for service %s/%s port %s", len(backendIPs),
			service.Namespace, service.Name, servicePort.Name)
		if len(backendIPs) == 0 {
			continue
		}
		targetPort, err := getTargetPort(servicePort)
		if err != nil {
			p.log.Warnf("Error determinig target port: %v", err)
			continue
		}
		p.log.Infof("NAT: %s:%d -> %+v :%d", service.Spec.ClusterIP, servicePort.Port, backendIPs, targetPort)
		err = p.vpp.AddNat44LB(service.Spec.ClusterIP, getServicePortProto(servicePort.Protocol),
			servicePort.Port, backendIPs, targetPort)
		if err != nil {
			return errors.Wrapf(err, "Error adding nat44 clusterIP lb config to %s", service.Spec.ClusterIP)
		}
	}
	return nil
}

func (p *Service44Provider) DelClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	// For each port, build list of backends and add to VPP
	for _, servicePort := range service.Spec.Ports {
		backendIPs := getServiceBackendIPs(&servicePort, ep)

		p.log.Debugf("%d backends found for service %s/%s port %s", len(backendIPs),
			service.Namespace, service.Name, servicePort.Name)
		if len(backendIPs) == 0 {
			continue
		}
		err = p.vpp.DelNat44LB(service.Spec.ClusterIP, getServicePortProto(servicePort.Protocol),
			servicePort.Port, len(backendIPs))
		if err != nil {
			return errors.Wrap(err, "Error deleting nat44 lb config")
		}
	}

	err = p.delNATAddress(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error deleting nat44 address")
	}
	return nil
}
