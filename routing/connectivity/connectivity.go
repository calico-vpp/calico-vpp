// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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

package connectivity

import (
	"fmt"
	"net"

	"github.com/calico-vpp/vpplink"
	"github.com/sirupsen/logrus"
)

type NodeConnectivity struct {
	Dst     net.IPNet
	NextHop net.IP
}

func (cn *NodeConnectivity) String() string {
	return fmt.Sprintf("%s-%s", cn.Dst.String(), cn.NextHop.String())
}

type ConnectivityProvider interface {
	AddConnectivity(cn *NodeConnectivity) error
	DelConnectivity(cn *NodeConnectivity) error
}

type ConnectivityProviderData struct {
	vpp  *vpplink.VppLink
	log  *logrus.Entry
	ipv6 *net.IP
	ipv4 *net.IP
}

func NewConnectivityProviderData(vpp *vpplink.VppLink, log *logrus.Entry, ipv6 *net.IP, ipv4 *net.IP) *ConnectivityProviderData {
	return &ConnectivityProviderData{
		vpp:  vpp,
		log:  log,
		ipv6: ipv6,
		ipv4: ipv4,
	}
}

func (s *ConnectivityProviderData) getNodeIP(isv6 bool) net.IP {
	if isv6 {
		return *s.ipv6
	} else {
		return *s.ipv4
	}
}
