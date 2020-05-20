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
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type CalicoServiceProvider struct {
	log      *logrus.Entry
	vpp      *vpplink.VppLink
	s        *Server
	entryMap map[string]*types.CalicoTranslateEntry
}

func newCalicoServiceProvider(s *Server) (p *CalicoServiceProvider) {
	p = &CalicoServiceProvider{
		log: s.log.WithField("service", "calico"),
		vpp: s.vpp,
		s:   s,
	}
	return p
}

func (p *CalicoServiceProvider) Init() (err error) {
	p.entryMap = make(map[string]*types.CalicoTranslateEntry)
	return nil
}

func (p *CalicoServiceProvider) AnnounceInterface(swIfIndex uint32, isTunnel bool, isWithdrawal bool) error {
	return nil
}

func (p *CalicoServiceProvider) AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) error {
	return nil /* Nothing to do */
}

func (p *CalicoServiceProvider) UpdateNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *CalicoServiceProvider) AddNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *CalicoServiceProvider) DelNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *CalicoServiceProvider) UpdateClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.log.Infof("NAT: Update ClusterIP")
	return p.AddClusterIP(service, ep)
}

func getCalicoEntry(servicePort *v1.ServicePort, service *v1.Service, ep *v1.Endpoints) (entry *types.CalicoTranslateEntry, err error) {
	proto := getServicePortProto(servicePort.Protocol)
	targetPort, err := getTargetPort(*servicePort)
	if err != nil {
		return nil, errors.Wrapf(err, "Error determinig target port")
	}
	backendIPs := getServiceBackendIPs(servicePort, ep)
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	return &types.CalicoTranslateEntry{
		SrcPort:    uint16(servicePort.Port),
		Vip:        clusterIP,
		Proto:      proto,
		DestPort:   uint16(targetPort),
		BackendIPs: backendIPs,
	}, nil
}

func (p *CalicoServiceProvider) AddClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.log.Infof("NAT: Add ClusterIP")
	for _, servicePort := range service.Spec.Ports {
		entry, err := getCalicoEntry(&servicePort, service, ep)
		if err != nil {
			p.log.Warnf("NAT:Error getting service entry: %v", err)
			continue
		}
		p.log.Infof("NAT: (add) %s", entry.String())
		entryID, err := p.vpp.CalicoTranslateAdd(entry)
		if err != nil {
			return errors.Wrapf(err, "NAT:Error adding clusterIP %s", entry.String())
		}
		entry.ID = entryID
		p.entryMap[servicePort.Name] = entry
	}
	return nil
}

func (p *CalicoServiceProvider) DelClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	p.log.Infof("NAT: Add ClusterIP")
	for _, servicePort := range service.Spec.Ports {
		entry, ok := p.entryMap[servicePort.Name]
		if !ok {
			p.log.Infof("NAT: (del) Entry not found for %s", servicePort.Name)
			continue
		}
		p.log.Infof("NAT: (del) %s", entry.String())
		err = p.vpp.CalicoTranslateDel(entry.ID)
		if err != nil {
			return errors.Wrapf(err, "NAT: (del) Error deleting entry %s", entry.String())
		}
		delete(p.entryMap, servicePort.Name)
	}
	return nil
}
