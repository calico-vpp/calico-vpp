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
	"fmt"
	"net"
	"syscall"

	pb "github.com/calico-vpp/calico-vpp/cni/proto"
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/calico-vpp/routing"
	"github.com/calico-vpp/calico-vpp/services"
	"github.com/calico-vpp/vpplink"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type Server struct {
	log             *logrus.Entry
	grpcServer      *grpc.Server
	vpp             *vpplink.VppLink
	socketListener  net.Listener
	routingServer   *routing.Server
	servicesServer  *services.Server
	podInterfaceMap map[string]*pb.AddRequest
}

func (s *Server) Add(ctx context.Context, in *pb.AddRequest) (*pb.AddReply, error) {
	s.log.Infof("CNI server got Add request")
	ifName, contMac, err := s.AddVppInterface(in, true)
	out := &pb.AddReply{
		Successful:    true,
		InterfaceName: ifName,
		ContainerMac:  contMac,
	}
	if err != nil {
		s.log.Warnf("Interface creation failed")
		out.Successful = false
		out.ErrorMessage = err.Error()
	} else {
		s.podInterfaceMap[addKey(in)] = in
		s.log.Infof("Interface creation successful: %s", ifName)
	}
	return out, nil
}

func (p *Server) OnVppRestart() {
	for name, in := range p.podInterfaceMap {
		_, _, err := p.AddVppInterface(in, false)
		if err != nil {
			p.log.Errorf("Error re-injecting interface %s : %v", name, err)
		}
	}
}

func addKey(in *pb.AddRequest) string {
	return fmt.Sprintf("%s--%s", in.GetNetns(), in.GetInterfaceName())
}

func delKey(in *pb.DelRequest) string {
	return fmt.Sprintf("%s--%s", in.GetNetns(), in.GetInterfaceName())
}

func (s *Server) Del(ctx context.Context, in *pb.DelRequest) (*pb.DelReply, error) {
	s.log.Infof("CNI server got Del request")
	err := s.DelVppInterface(in)
	if err != nil {
		s.log.Warnf("Interface deletion failed")
		return &pb.DelReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	delete(s.podInterfaceMap, delKey(in))
	s.log.Infof("Interface deletion successful")
	return &pb.DelReply{
		Successful: true,
	}, nil
}

func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
	syscall.Unlink(config.CNIServerSocket)
}

// Serve runs the grpc server for the Calico CNI backend API
func NewServer(v *vpplink.VppLink, rs *routing.Server, ss *services.Server, l *logrus.Entry) (*Server, error) {
	lis, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		l.Fatalf("failed to listen on %s: %v", config.CNIServerSocket, err)
		return nil, err
	}
	server := &Server{
		vpp:             v,
		log:             l,
		routingServer:   rs,
		servicesServer:  ss,
		socketListener:  lis,
		grpcServer:      grpc.NewServer(),
		podInterfaceMap: make(map[string]*pb.AddRequest),
	}
	pb.RegisterCniDataplaneServer(server.grpcServer, server)
	l.Infof("CNI server starting")
	return server, nil
}

func (s *Server) Serve() {
	err := s.grpcServer.Serve(s.socketListener)
	if err != nil {
		s.log.Fatalf("failed to serve: %v", err)
	}
}
