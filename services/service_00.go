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
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type Service00Provider struct {
	log *logrus.Entry
	vpp *vpplink.VppLink
	s   *Server
}

func newService00Provider(s *Server) (p *Service00Provider) {
	p = &Service00Provider{
		log: s.log.WithField("service", "nat00"),
		vpp: s.vpp,
		s:   s,
	}
	return p
}

func (p *Service00Provider) Init() (err error) {
	return nil
}

func (p *Service00Provider) AnnounceInterface(swIfIndex uint32, isTunnel bool, isWithdrawal bool) error {
	return nil
}

func (p *Service00Provider) AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) error {
	return nil /* Nothing to do */
}

func (p *Service00Provider) UpdateNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *Service00Provider) AddNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *Service00Provider) DelNodePort(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *Service00Provider) UpdateClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *Service00Provider) AddClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}

func (p *Service00Provider) DelClusterIP(service *v1.Service, ep *v1.Endpoints) (err error) {
	return nil
}
