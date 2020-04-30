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
	"sync"

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
	nat44backendIPmap  map[string]*types.Nat44Entry
	lock               sync.Mutex
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
	p.nat44backendIPmap = make(map[string]*types.Nat44Entry)
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
		p.log.Infof("NAT: Adding address %s", addr)
		ip := net.ParseIP(addr)
		return p.vpp.AddNat44Address(ip)
	}
	return nil
}

func (p *Service44Provider) delNATAddress(addr string) error {
	if refCnt, ok := p.nat44addressRefCnt[addr]; ok {
		if refCnt > 1 {
			p.nat44addressRefCnt[addr] = refCnt - 1
		} else if refCnt == 1 {
			delete(p.nat44addressRefCnt, addr)
			p.log.Infof("NAT: Deleting address %s", addr)
			ip := net.ParseIP(addr)
			return p.vpp.DelNat44Address(ip)
		} else {
			p.log.Errorf("Wrong refCnt : %d", refCnt)
		}
	} else {
		p.log.Errorf("Address wasn't added : %s", addr)
	}
	return nil
}

func (p *Service44Provider) UpdateNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Infof("NAT: Update ClusterIP")
	for _, servicePort := range service.Spec.Ports {
		entry, err := getServiceEntry(&servicePort, service, ep)
		if err != nil {
			p.log.Warnf("Error getting service entry: %v", err)
			continue
		}
		previousEntry := p.nat44backendIPmap[servicePort.Name]
		add, del := p.getAddedAndRemoved(entry, previousEntry)
		p.log.Infof("NAT: (upd-del) %s", del.String())
		err = p.vpp.DelNat44LB(del)
		if err != nil {
			return errors.Wrapf(err, "Error Updating(del) Nodeport %s", del.String())
		}
		p.log.Infof("NAT: (upd-add) %s", add.String())
		err = p.vpp.AddNat44LB(add)
		if err != nil {
			return errors.Wrapf(err, "Error Updating(add) Nodeport %s", add.String())
		}
		p.nat44backendIPmap[servicePort.Name] = entry
	}
	return nil
}

func (p *Service44Provider) AddNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Infof("NAT: Add NodePort")
	err = p.addNATAddress(service.Spec.ClusterIP)
	if err != nil {
		p.log.Errorf("Error adding nat44 Nodeport address %s %+v", service.Spec.ClusterIP, err)
	}
	nodeIp, _, err := p.s.getNodeIP()
	if err != nil {
		return errors.Wrap(err, "Error getting Node IP")
	}
	for _, servicePort := range service.Spec.Ports {
		entry, err := getServiceEntry(&servicePort, service, ep)
		npEntry := getNodePortEntry(entry, nodeIp)
		p.log.Infof("NAT: (np) %s", entry.String())
		err = p.vpp.AddNat44LB(entry)
		if err != nil {
			return errors.Wrapf(err, "Error adding NodePort %s", entry.String())
		}
		p.nat44backendIPmap[servicePort.Name] = entry
		p.log.Infof("NAT: (np) %s", npEntry.String())
		err = p.vpp.AddNat44LB(npEntry)
		if err != nil {
			return errors.Wrapf(err, "Error adding NodePort %s", npEntry.String())
		}
	}
	return nil
}

func (p *Service44Provider) DelNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Infof("NAT: Del NodePort")
	nodeIp, _, err := p.s.getNodeIP()
	if err != nil {
		return errors.Wrap(err, "Error getting Node IP")
	}
	for _, servicePort := range service.Spec.Ports {
		entry := p.nat44backendIPmap[servicePort.Name]
		delete(p.nat44backendIPmap, servicePort.Name)
		npEntry := getNodePortEntry(entry, nodeIp)

		p.log.Infof("NAT: (del np) %s", entry.String())
		err = p.vpp.DelNat44LB(entry)
		if err != nil {
			return errors.Wrapf(err, "Error deleting NodePort %s", entry.String())
		}
		p.log.Infof("NAT: (del np) %s", npEntry.String())
		err = p.vpp.DelNat44LB(npEntry)
		if err != nil {
			return errors.Wrapf(err, "Error deleting NodePort %s", npEntry.String())
		}
	}

	err = p.delNATAddress(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error deleting nat44 address")
	}
	return nil
}

// func keys(m map[string]bool) []string {
// 	keys := make([]string, 0, len(m))
//     for k := range m {
//         keys = append(keys, k)
//     }
//     return keys
// }

func lstToMap(lst []net.IP) map[string]bool {
	newMap := make(map[string]bool)
	for _, i := range lst {
		newMap[i.String()] = true
	}
	return newMap
}

func (p *Service44Provider) getAddedAndRemoved(new *types.Nat44Entry, prev *types.Nat44Entry) (*types.Nat44Entry, *types.Nat44Entry) {
	nl := len(new.BackendIPs)
	pl := len(prev.BackendIPs)
	if (nl == 1 && pl > 1) || (pl == 1 && nl > 1) {
		// Change between 1:1 / LB need delete & add
		return new, prev
	}
	if new.BackendPort != prev.BackendPort {
		p.log.Infof("NAT: BackendPort changed for service")
		return new, prev
	}
	if new.ServicePort != prev.ServicePort {
		p.log.Infof("NAT: ServicePort changed for service")
		return new, prev
	}
	if new.Protocol != prev.Protocol {
		p.log.Infof("NAT: Protocol changed for service")
		return new, prev
	}

	newMap := lstToMap(new.BackendIPs)
	prevMap := lstToMap(prev.BackendIPs)
	add := *new
	del := *prev
	add.BackendIPs = make([]net.IP, 0, nl)
	del.BackendIPs = make([]net.IP, 0, pl)
	for _, i := range new.BackendIPs {
		if _, ok := prevMap[i.String()]; !ok {
			add.BackendIPs = append(add.BackendIPs, i)
		}
	}
	for _, i := range prev.BackendIPs {
		if _, ok := newMap[i.String()]; !ok {
			del.BackendIPs = append(del.BackendIPs, i)
		}
	}
	return &add, &del
}

func getNodePortEntry(entry *types.Nat44Entry, nodeIp net.IP) *types.Nat44Entry {
	npEntry := *entry
	npEntry.ServiceIP = nodeIp
	return &npEntry
}

func getServiceEntry(servicePort *v1.ServicePort, service *v1.Service, ep *v1.Endpoints) (entry *types.Nat44Entry, err error) {
	proto := getServicePortProto(servicePort.Protocol)
	targetPort, err := getTargetPort(*servicePort)
	if err != nil {
		return nil, errors.Wrapf(err, "Error determinig target port")
	}
	backendIPs := getServiceBackendIPs(servicePort, ep)
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	return &types.Nat44Entry{
		ServiceIP:   clusterIP,
		ServicePort: servicePort.Port,
		Protocol:    proto,
		BackendIPs:  backendIPs,
		BackendPort: targetPort,
	}, nil
}

func (p *Service44Provider) UpdateClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Infof("NAT: Update ClusterIP")
	for _, servicePort := range service.Spec.Ports {
		entry, err := getServiceEntry(&servicePort, service, ep)
		if err != nil {
			p.log.Warnf("Error getting service entry: %v", err)
			continue
		}
		previousEntry := p.nat44backendIPmap[servicePort.Name]
		add, del := p.getAddedAndRemoved(entry, previousEntry)
		p.log.Infof("NAT: (upd-del) %s", del.String())
		err = p.vpp.DelNat44LB(del)
		if err != nil {
			return errors.Wrapf(err, "Error Updating(del) clusterIP %s", del.String())
		}
		p.log.Infof("NAT: (upd-add) %s", add.String())
		err = p.vpp.AddNat44LB(add)
		if err != nil {
			return errors.Wrapf(err, "Error Updating(add) clusterIP %s", add.String())
		}
		p.nat44backendIPmap[servicePort.Name] = entry
	}
	return nil
}

func (p *Service44Provider) AddClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Infof("NAT: Add ClusterIP")
	err = p.addNATAddress(service.Spec.ClusterIP)
	if err != nil {
		p.log.Errorf("Error adding nat44 address %s %+v", service.Spec.ClusterIP, err)
	}
	for _, servicePort := range service.Spec.Ports {
		entry, err := getServiceEntry(&servicePort, service, ep)
		if err != nil {
			p.log.Warnf("Error getting service entry: %v", err)
			continue
		}
		p.log.Infof("NAT: %s", entry.String())
		err = p.vpp.AddNat44LB(entry)
		if err != nil {
			return errors.Wrapf(err, "Error adding clusterIP %s", entry.String())
		}
		p.nat44backendIPmap[servicePort.Name] = entry
	}
	return nil
}

func (p *Service44Provider) DelClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Infof("NAT: Del ClusterIP")
	for _, servicePort := range service.Spec.Ports {
		entry := p.nat44backendIPmap[servicePort.Name]
		delete(p.nat44backendIPmap, servicePort.Name)
		p.log.Infof("NAT: (del) %s", entry.String())
		err = p.vpp.DelNat44LB(entry)
		if err != nil {
			return errors.Wrapf(err, "Error deleting clusterIP %s", entry.String())
		}
	}

	err = p.delNATAddress(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "Error deleting nat44 address")
	}
	return nil
}
