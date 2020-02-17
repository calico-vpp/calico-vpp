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

package cni

import (
	"context"
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
	pb "github.com/calico-vpp/calico-vpp/cni/proto"
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/calico-vpp/vpp_client"
	"google.golang.org/grpc"
)

type server struct {
}

var (
	logger     *logrus.Entry
	grpcServer *grpc.Server
	vpp        *vpp_client.VppInterface
)

func (s *server) Add(ctx context.Context, in *pb.AddRequest) (*pb.AddReply, error) {
	logger.Infof("CNI server got Add request")
	ifName, contMac, err := addVppInterface(vpp, logger, in)
	out := &pb.AddReply{
		Successful:    true,
		InterfaceName: ifName,
		ContainerMac:  contMac,
	}
	if err != nil {
		logger.Warnf("Interface creation failed")
		out.Successful = false
		out.ErrorMessage = err.Error()
	} else {
		logger.Infof("Interface creation successful: %s", ifName)
	}
	return out, nil
}

func (s *server) Del(ctx context.Context, in *pb.DelRequest) (*pb.DelReply, error) {
	logger.Infof("CNI server got Del request")
	err := delVppInterface(vpp, logger, in)
	if err != nil {
		logger.Warnf("Interface deletion failed")
		return &pb.DelReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	logger.Infof("Interface deletion successful")
	return &pb.DelReply{
		Successful: true,
	}, nil
}

func GracefulStop() {
	grpcServer.GracefulStop()
	syscall.Unlink(config.CNIServerSocket)
}

// Serve runs the grpc server for the Calico CNI backend API
func Run(v *vpp_client.VppInterface, l *logrus.Entry) {
	var err error
	logger = l
	vpp = v

	lis, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		logger.Fatalf("failed to listen on %s: %v", config.CNIServerSocket, err)
	}
	grpcServer = grpc.NewServer()
	pb.RegisterCniDataplaneServer(grpcServer, &server{})
	logger.Infof("CNI server starting")

	if err := grpcServer.Serve(lis); err != nil {
		logger.Fatalf("failed to serve: %v", err)
	}
}
