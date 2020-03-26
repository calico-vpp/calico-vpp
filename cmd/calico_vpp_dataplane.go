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
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/calico-vpp/calico-vpp/cni"
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/calico-vpp/routing"
	"github.com/calico-vpp/calico-vpp/services"
	"github.com/calico-vpp/vpplink"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func waitForVppManager() error {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(config.VppManagerStatusFile)
		if err == nil && strings.TrimSpace(string(dat[:])) == "1" {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return errors.Errorf("Vpp manager not ready after 20 tries")
}

func main() {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	err := waitForVppManager()
	if err != nil {
		log.Errorf("Vpp Manager not started: %v", err)
		return
	}

	vpp, err := vpplink.NewVppLink(config.VppAPISocket, log.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		log.Errorf("Cannot create VPP client: %v", err)
		return
	}

	go routing.Run(vpp, log.WithFields(logrus.Fields{"component": "routing"}))
	<-routing.ServerRunning

	go services.Run(vpp, log.WithFields(logrus.Fields{"component": "services"}))
	go cni.Run(vpp, log.WithFields(logrus.Fields{"component": "cni"}))

	<-signalChannel
	log.Infof("SIGINT received, exiting")
	routing.GracefulStop()
	cni.GracefulStop()
	services.GracefulStop()
	vpp.Close()
}
