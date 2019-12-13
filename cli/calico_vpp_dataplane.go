package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vpp-calico/vpp-calico/cni"
	"github.com/vpp-calico/vpp-calico/routing"
	"github.com/vpp-calico/vpp-calico/vpp_client"
)

const (
	vppSocket = "/var/run/vpp/vpp-api.sock"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	vpp, err := vpp_client.NewVppInterface(vppSocket, logger.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		logger.Errorf("Cannot create VPP client: %v", err)
		return
	}

	go cni.Run(vpp, logger.WithFields(logrus.Fields{"component": "cni"}))
	go routing.Run(vpp, logger.WithFields(logrus.Fields{"component": "routing"}))

	<-signalChannel
	logger.Infof("SIGINT received, exiting")
	routing.GracefulStop()
	cni.GracefulStop()
	vpp.Close()
}
