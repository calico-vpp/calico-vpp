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
	"github.com/calico-vpp/calico-vpp/common"
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/calico-vpp/routing"
	"github.com/calico-vpp/calico-vpp/services"
	"github.com/calico-vpp/vpplink"
	"github.com/sirupsen/logrus"
)

func main() {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	err := config.LoadConfig(log)
	if err != nil {
		log.Errorf("Error loading configuration: %v", err)
		return
	}

	err = common.WritePidToFile()
	if err != nil {
		log.Errorf("Error writing pidfile: %v", err)
		return
	}

	err = common.WaitForVppManager()
	if err != nil {
		log.Errorf("Vpp Manager not started: %v", err)
		return
	}

	vpp, err := vpplink.NewVppLink(config.VppAPISocket, log.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		log.Errorf("Cannot create VPP client: %v", err)
		return
	}

	serviceServer, err := services.NewServer(vpp, log.WithFields(logrus.Fields{"component": "services"}))
	if err != nil {
		log.Errorf("Failed to create services server")
		log.Fatal(err)
	}
	routingServer, err := routing.NewServer(vpp, serviceServer, log.WithFields(logrus.Fields{"component": "routing"}))
	if err != nil {
		log.Errorf("Failed to create services server")
		log.Fatal(err)
	}
	cniServer, err := cni.NewServer(
		vpp,
		routingServer,
		serviceServer,
		log.WithFields(logrus.Fields{"component": "cni"}),
	)
	if err != nil {
		log.Errorf("Failed to create services server")
		log.Fatal(err)
	}
	go routingServer.Serve()
	<-routing.ServerRunning

	go serviceServer.Serve()
	go cniServer.Serve()

	go common.HandleVppManagerRestart(log, vpp, routingServer, cniServer, serviceServer)

	<-signalChannel
	log.Infof("SIGINT received, exiting")
	routingServer.Stop()
	cniServer.Stop()
	serviceServer.Stop()
	vpp.Close()
}
