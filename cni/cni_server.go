package cni

import (
	"context"
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
	pb "github.com/vpp-calico/vpp-calico/cni/proto"
	"github.com/vpp-calico/vpp-calico/vpp_client"
	"google.golang.org/grpc"
)

type server struct {
}

const (
	serverSocket = "/var/run/calico/cni-server.sock"
)

var (
	logger     *logrus.Entry
	grpcServer *grpc.Server
	vpp        *vpp_client.VppInterface
)

func (s *server) Add(ctx context.Context, in *pb.AddRequest) (*pb.AddReply, error) {
	logger.Infof("CNI server got Add request")
	ifName, contMac, err := addVppInterface(logger, in)
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
	err := delVppInterface(logger, in)
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
	syscall.Unlink(serverSocket)
}

// Serve runs the grpc server for the Calico CNI backend API
func Run(v *vpp_client.VppInterface, l *logrus.Entry) {
	var err error
	logger = l
	vpp = v

	lis, err := net.Listen("unix", serverSocket)
	if err != nil {
		logger.Fatalf("failed to listen on %s: %v", serverSocket, err)
	}
	grpcServer = grpc.NewServer()
	pb.RegisterCniDataplaneServer(grpcServer, &server{})
	logger.Infof("CNI server starting")

	if err := grpcServer.Serve(lis); err != nil {
		logger.Fatalf("failed to serve: %v", err)
	}
}
