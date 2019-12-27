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
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	vppcore "git.fd.io/govpp.git/core"
    govpp "git.fd.io/govpp.git"
	vppapi "git.fd.io/govpp.git/api"
)

type VppInterface struct {
	lock   sync.Mutex
	conn   *vppcore.Connection
	ch     vppapi.Channel
	socket string
	log    *logrus.Entry
}

func (v *VppInterface) GetChannel() (vppapi.Channel, error) {
	return v.conn.NewAPIChannel()
}

func NewVppInterface(socket string, logger *logrus.Entry) (*VppInterface, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		logger.Errorf("cannot connect to VPP on socket %s", socket)
		return nil, fmt.Errorf("cannot connect to VPP on socket %s", socket)
	}

	// Open channel
	ch, err := conn.NewAPIChannel()
	if err != nil {
		logger.Errorf("VPP API channel creation failed")
		return nil, fmt.Errorf("channel creation failed")
	}

	return &VppInterface{
		conn:   conn,
		ch:     ch,
		socket: socket,
		log:    logger,
	}, nil
}

func (v *VppInterface) Close() {
	if v.ch != nil {
		v.ch.Close()
	}
	if v.conn != nil {
		v.conn.Disconnect()
	}
}
