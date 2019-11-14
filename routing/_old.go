package routing

import (
	"context"
	"fmt"
	"io"
	"time"

	vppcore "git.fd.io/govpp.git/core"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"local.local/vpp-calico-dataplane/routing/gobgpapi"
)

var (
	gobgpSocket                         = "localhost:50051"
	gobgpClient gobgpapi.GobgpApiClient = nil
	vppSocket                           = ""
	vppClient   *vppcore.Connection     = nil
	logger      *logrus.Entry           = nil
	timeout                             = time.Second
)

func AddLocalRoute() error {
	return nil
}

func DelLocalRoute() error {
	return nil
}

func Start(l *logrus.Entry) error {
	logger = l
	// Connect to GoBGP
	gobgpConn, err := grpc.Dial(gobgpSocket, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("cannot connect to gobgp: %v", err)
	}
	gobgpClient = gobgpapi.NewGobgpApiClient(gobgpConn)

	// Connect to VPP
	// vppConn, err := govpp.Connect(vppSocket)
	// if err != nil {
	// 	logger.Errorf("cannot connect to VPP")
	// 	return fmt.Errorf("cannot connect to VPP")
	// }

	go run() // It's good for your health
	return nil
}

// run dumps the GoBGP routes into VPP and then watches for updates
// and keeps VPP in sync until GracefulStop is called
func run() {
	// TODO better route sync. For now we just pull all the routes from gobgpd and install them into VPP
	req := &gobgpapi.MonitorTableRequest{
		TableType: gobgpapi.TableType_GLOBAL,
		Current:   true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	responseStream, err := gobgpClient.MonitorTable(ctx, req)
	if err != nil {
		logger.Fatalf("Error sending request to gobgp: %v", err)
	}
	for {
		update, err := responseStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Fatalf("%+v.MonitorTable() = _, %v", gobgpClient, err)
		}
		path := update.Path
		// Skip if next-hop is ourselves, or if we dont know how to handle the message (not a plain prefix)
		nlriType := path.Nlri.TypeUrl
		switch nlriType {
		case "gobgpapi.IPAddressPrefix":
			logger.Warnf("Got my little baby!")
		default:
			logger.Warnf("Got NlriType: %s", nlriType)
			continue
		}
		if !path.Best {
			logger.Debugf("Skipping non-best path %+v", path)
			continue
		}
		// TODO
		if path.IsWithdraw {
			// Remove route
		} else {
			// Install route
		}
	}
}

func GracefulStop() error {
	//gobgpConn.Close()
	//vppConn.Disconnect()
	return nil
}
