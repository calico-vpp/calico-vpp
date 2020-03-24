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

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/calico-vpp/calico-vpp/cni"
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/calico-vpp/routing"
	"github.com/calico-vpp/calico-vpp/services"
	"github.com/calico-vpp/calico-vpp/vpp_client"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	vpp, err := vpp_client.NewVppInterface(config.VppAPISocket, logger.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		logger.Errorf("Cannot create VPP client: %v", err)
		return
	}

	go routing.Run(vpp, logger.WithFields(logrus.Fields{"component": "routing"}))
	<-routing.ServerRunning

	go services.Run(vpp, logger.WithFields(logrus.Fields{"component": "services"}))
	go cni.Run(vpp, logger.WithFields(logrus.Fields{"component": "cni"}))

	<-signalChannel
	logger.Infof("SIGINT received, exiting")
	routing.GracefulStop()
	cni.GracefulStop()
	services.GracefulStop()
	vpp.Close()
}
