package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vpp-calico/vpp-calico/cni"
	"github.com/vpp-calico/vpp-calico/routing"
)

func main() {
	logger := logrus.New()
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	go cni.Run(logger.WithFields(logrus.Fields{"component": "cni"}))
	go routing.Run(logger.WithFields(logrus.Fields{"component": "routing"}))

	<-signalChannel
	logger.Infof("SIGINT received, exiting")
	routing.GracefulStop()
	cni.GracefulStop()
}
