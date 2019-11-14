package main

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"local.local/vpp-calico-dataplane/cni/proto"
)

func doTest() error {
	fmt.Println("Creating container interface using external networking")

	address := "unix:///tmp/cni-server.sock"
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("cannot connect to external dataplane: %v", err)
	}
	c := proto.NewCniDataplaneClient(conn)

	request := &proto.AddRequest{
		InterfaceName:            "eth0",
		Netns:                    "/var/run/netns/testing",
		DesiredHostInterfaceName: "",
		ContainerIps:             make([]*proto.IPConfig, 0),
		ContainerRoutes:          make([]*proto.IPNet, 0),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	reply, err := c.Add(ctx, request)
	if err != nil {
		return err
	}
	if !reply.GetSuccessful() {
		return fmt.Errorf("external dataplane error: %s", reply.GetErrorMessage())
	}
	return nil
}

func doTest2() error {
	fmt.Println("Deleting container interface using external networking")

	address := "unix:///tmp/cni-server.sock"
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("cannot connect to external dataplane: %v", err)
	}
	c := proto.NewCniDataplaneClient(conn)

	request := &proto.DelRequest{
		InterfaceName: "eth0",
		Netns:         "/var/run/netns/testing",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	reply, err := c.Del(ctx, request)
	if err != nil {
		return err
	}
	if !reply.GetSuccessful() {
		return fmt.Errorf("external dataplane error: %s", reply.GetErrorMessage())
	}
	return nil
}

func main() {
	fmt.Println(doTest())
	fmt.Println(doTest2())
}
