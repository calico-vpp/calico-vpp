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
	log          *logrus.Entry
	vpp          *vpplink.VppLink
	s            *Server
	clusterIPMap map[string]*types.CalicoTranslateEntry
	nodePortMap  map[string]*types.CalicoTranslateEntry
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
	p.clusterIPMap = make(map[string]*types.CalicoTranslateEntry)
	p.nodePortMap = make(map[string]*types.CalicoTranslateEntry)
	return nil
}

func getCalicoEntry(servicePort *v1.ServicePort, ep *v1.Endpoints, clusterIP net.IP) (entry *types.CalicoTranslateEntry, err error) {
	targetPort, err := getTargetPort(*servicePort)
	if err != nil {
		return nil, errors.Wrapf(err, "Error determinig target port")
	}
	return &types.CalicoTranslateEntry{
		SrcPort:    uint16(servicePort.Port),
		Vip:        clusterIP,
		Proto:      getServicePortProto(servicePort.Protocol),
		DestPort:   uint16(targetPort),
		BackendIPs: getServiceBackendIPs(servicePort, ep),
	}, nil
}

func getCalicoNodePortEntry(servicePort *v1.ServicePort, ep *v1.Endpoints, nodeIP net.IP) (entry *types.CalicoTranslateEntry, err error) {
	targetPort, err := getTargetPort(*servicePort)
	if err != nil {
		return nil, errors.Wrapf(err, "Error determinig target port")
	}
	return &types.CalicoTranslateEntry{
		SrcPort:    uint16(servicePort.NodePort),
		Vip:        nodeIP,
		Proto:      getServicePortProto(servicePort.Protocol),
		DestPort:   uint16(targetPort),
		BackendIPs: getServiceBackendIPs(servicePort, ep),
	}, nil
}

func (p *CalicoServiceProvider) AddServicePort(service *v1.Service, ep *v1.Endpoints, isNodePort bool) (err error) {
	clusterIP := net.ParseIP(service.Spec.ClusterIP)
	nodeIP := p.s.getNodeIP(vpplink.IsIP6(clusterIP))
	p.log.Infof("NAT: Add ClusterIP")
	for _, servicePort := range service.Spec.Ports {
		if entry, err := getCalicoEntry(&servicePort, ep, clusterIP); err == nil {
			p.log.Infof("NAT: (add) %s", entry.String())
			entryID, err := p.vpp.CalicoTranslateAdd(entry)
			if err != nil {
				return errors.Wrapf(err, "NAT:Error adding nodePort %s", entry.String())
			}
			entry.ID = entryID
			p.clusterIPMap[servicePort.Name] = entry
		} else {
			p.log.Warnf("NAT:Error getting service entry: %v", err)
		}
		if !isNodePort {
			continue
		}
		if entry, err := getCalicoNodePortEntry(&servicePort, ep, nodeIP); err == nil {
			p.log.Infof("NAT: (add) %s", entry.String())
			entryID, err := p.vpp.CalicoTranslateAdd(entry)
			if err != nil {
				return errors.Wrapf(err, "NAT:Error adding nodePort %s", entry.String())
			}
			entry.ID = entryID
			p.nodePortMap[servicePort.Name] = entry
		} else {
			p.log.Warnf("NAT:Error getting service entry: %v", err)
		}
	}
	return nil
}

func (p *CalicoServiceProvider) DelServicePort(service *v1.Service, ep *v1.Endpoints, isNodePort bool) (err error) {
	p.log.Infof("NAT: Add ClusterIP")
	for _, servicePort := range service.Spec.Ports {
		if entry, ok := p.clusterIPMap[servicePort.Name]; ok {
			p.log.Infof("NAT: (del) %s", entry.String())
			err = p.vpp.CalicoTranslateDel(entry.ID)
			if err != nil {
				return errors.Wrapf(err, "NAT: (del) Error deleting entry %s", entry.String())
			}
			delete(p.clusterIPMap, servicePort.Name)
		} else {
			p.log.Infof("NAT: (del) Entry not found for %s", servicePort.Name)
		}
		if !isNodePort {
			continue
		}
		if entry, ok := p.nodePortMap[servicePort.Name]; ok {
			p.log.Infof("NAT: (del) nodeport %s", entry.String())
			err = p.vpp.CalicoTranslateDel(entry.ID)
			if err != nil {
				return errors.Wrapf(err, "NAT: (del) Error deleting nodeport %s", entry.String())
			}
			delete(p.clusterIPMap, servicePort.Name)
		} else {
			p.log.Infof("NAT: (del) Entry not found for %s", servicePort.Name)
		}
	}
	return nil
}
