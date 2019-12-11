package cni

import (
	"context"
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
	pb "github.com/vpp-calico/vpp-calico/cni/proto"

	"google.golang.org/grpc"
)

type server struct {
}

const (
	serverSocket = "/var/run/calico/cni-server.sock"
	vppSocket    = ""
)

var (
	logger     *logrus.Entry
	grpcServer *grpc.Server
)

func (s *server) Add(ctx context.Context, in *pb.AddRequest) (*pb.AddReply, error) {
	ifName, contMac, err := addVppInterface(vppSocket, logger, in)
	out := &pb.AddReply{
		Successful:    true,
		InterfaceName: ifName,
		ContainerMac:  contMac,
	}
	if err != nil {
		out.Successful = false
		out.ErrorMessage = err.Error()
	}
	return out, nil
}

func (s *server) Del(ctx context.Context, in *pb.DelRequest) (*pb.DelReply, error) {
	err := delVppInterface(vppSocket, logger, in)
	if err != nil {
		return &pb.DelReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}
	return &pb.DelReply{
		Successful: true,
	}, nil
}

func GracefulStop() {
	grpcServer.GracefulStop()
	syscall.Unlink(serverSocket)
}

// Serve runs the grpc server for the Calico CNI backend API
func Run(l *logrus.Entry) {
	logger = l
	lis, err := net.Listen("unix", serverSocket)
	if err != nil {
		logger.Fatalf("failed to listen on %s: %v", serverSocket, err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterCniDataplaneServer(grpcServer, &server{})
	logger.Infof("CNI server starting")

	if err := grpcServer.Serve(lis); err != nil {
		logger.Fatalf("failed to serve: %v", err)
	}
}
