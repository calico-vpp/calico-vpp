// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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

package routing

import (
	"fmt"
	"net"
	"time"

	"github.com/calico-vpp/calico-vpp/common"
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/calico-vpp/routing/connectivity"
	"github.com/calico-vpp/calico-vpp/services"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	bgpapi "github.com/osrg/gobgp/api"
	bgpserver "github.com/osrg/gobgp/pkg/server"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	calicocliv3 "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoerr "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/calico-vpp/vpplink"

	"gopkg.in/tomb.v2"
)

const (
	aggregatedPrefixSetName = "aggregated"
	hostPrefixSetName       = "host"

	RTPROT_GOBGP = 0x11

	prefixWatchInterval = 5 * time.Second
)

var (
	bgpFamilyUnicastIPv4 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP, Safi: bgpapi.Family_SAFI_UNICAST}
	bgpFamilyUnicastIPv6 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_UNICAST}
	server               *Server
	ServerRunning        = make(chan int, 1)
)

type IpamCache interface {
	match(net.IPNet) *calicov3.IPPool
	update(calicov3.IPPool, bool) error
	sync() error
}

type Server struct {
	*common.CalicoVppServerData
	log             *logrus.Entry
	vpp             *vpplink.VppLink
	t               tomb.Tomb
	bgpServer       *bgpserver.BgpServer
	client          *calicocli.Client
	clientv3        calicocliv3.Interface
	defaultBGPConf  *calicov3.BGPConfigurationSpec
	ipv4            net.IP
	ipv6            net.IP
	ipv4Net         *net.IPNet
	ipv6Net         *net.IPNet
	hasV4           bool
	hasV6           bool
	ipam            IpamCache
	reloadCh        chan string
	prefixReady     chan int
	servicesServer  *services.Server
	connectivityMap map[string]*connectivity.NodeConnectivity
	localAddressMap map[string]*net.IPNet
	ShouldStop      bool
	// Connectivity providers
	flat  *connectivity.FlatL3Provider
	ipip  *connectivity.IpipProvider
	ipsec *connectivity.IpsecProvider
}

func NewServer(vpp *vpplink.VppLink, ss *services.Server, l *logrus.Entry) (*Server, error) {
	logrus.SetLevel(config.BgpLogLevel) // This sets the log level for the GoBGP server

	calicoCli, err := calicocli.NewFromEnv()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create calico v1 api client")
	}
	calicoCliV3, err := calicocliv3.NewFromEnv()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create calico v3 api client")
	}

	server := Server{
		client:          calicoCli,
		clientv3:        calicoCliV3,
		reloadCh:        make(chan string),
		prefixReady:     make(chan int),
		vpp:             vpp,
		log:             l,
		servicesServer:  ss,
		connectivityMap: make(map[string]*connectivity.NodeConnectivity),
		localAddressMap: make(map[string]*net.IPNet),
	}
	providerData := connectivity.NewConnectivityProviderData(
		server.vpp, server.log, &server.ipv6, &server.ipv4,
	)
	server.flat = connectivity.NewFlatL3Provider(providerData)
	server.ipip = connectivity.NewIPIPProvider(providerData)
	server.ipsec = connectivity.NewIPsecProvider(providerData)

	BGPConf, err := server.getDefaultBGPConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error getting default BGP configuration")
	}
	server.defaultBGPConf = BGPConf
	return &server, nil
}

func (s *Server) fetchNodeIPs() (node *calicov3.Node, err error) {
	node, err = s.clientv3.Nodes().Get(
		context.Background(),
		config.NodeName,
		options.GetOptions{},
	)
	if err != nil {
		return nil, errors.Wrap(err, "cannot fetch current node")
	}

	if node.Spec.BGP == nil {
		return nil, fmt.Errorf("Calico is running in policy-only mode")
	}
	s.ipv4, s.ipv4Net, err = net.ParseCIDR(node.Spec.BGP.IPv4Address)
	s.hasV4 = (err == nil)
	s.ipv6, s.ipv6Net, err = net.ParseCIDR(node.Spec.BGP.IPv6Address)
	s.hasV6 = (err == nil)
	s.log.Infof("Fetched node IPs v4:%s, v6:%s", s.ipv4.String(), s.ipv6.String())
	return node, nil
}

func (s *Server) createAndStartBGP() error {
	globalConfig, err := s.getGlobalConfig()
	if err != nil {
		return fmt.Errorf("cannot get global configuration: ", err)
	}
	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxSize),
		grpc.MaxSendMsgSize(maxSize),
	}
	s.bgpServer = bgpserver.NewBgpServer(
		bgpserver.GrpcListenAddress("localhost:50051"),
		bgpserver.GrpcOption(grpcOpts),
	)

	s.t.Go(func() error { s.bgpServer.Serve(); return fmt.Errorf("bgpServer Serve returned") })

	return s.bgpServer.StartBgp(
		context.Background(),
		&bgpapi.StartBgpRequest{Global: globalConfig},
	)
}

func (s *Server) serveOne() error {
	s.log.Infof("Routing server started")
	node, err := s.fetchNodeIPs()
	if err != nil {
		return errors.Wrap(err, "cannot get node ips")
	}

	err = s.createAndStartBGP()
	if err != nil {
		return errors.Wrap(err, "failed to start BGP server")
	}

	err = s.initialPolicySetting()
	if err != nil {
		return errors.Wrap(err, "error configuring initial policies")
	}
	/* Restore the previous config in case we restarted */
	s.RestoreLocalAddresses()

	/* We should start watching from our getNodeIPs change call */
	s.t.Go(func() error { return fmt.Errorf("watchNodes: %s", s.watchNodes(node.ResourceVersion)) })

	s.ipam = newIPAMCache(s.log.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}), s.clientv3, s.ipamUpdateHandler)
	// sync IPAM and call ipamUpdateHandler
	s.t.Go(func() error { return fmt.Errorf("syncIPAM: %s", s.ipam.sync()) })
	// watch prefix assigned and announce to other BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchPrefix: %s", s.watchPrefix()) })
	// watch BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchBGPPeers: %s", s.watchBGPPeers()) })

	// TODO need to watch BGP configurations and restart in case of changes
	// Need to get initial BGP config here, pass it to the watchers that need it,
	// and pass its revision to the BGP config and nodes watchers

	// watch routes from other BGP peers and update FIB
	s.t.Go(func() error { return fmt.Errorf("watchBGPPath: %s", s.watchBGPPath()) })

	// watch routes added by kernel and announce to other BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchKernelRoute: %s", s.watchKernelRoute()) })

	ServerRunning <- 1
	<-s.t.Dying()
	s.log.Warnf("routing tomb returned %v", s.t.Err())

	err = s.cleanUpRoutes()
	if err != nil {
		return errors.Wrapf(err, "%s, also failed to clean up routes which we injected", s.t.Err())
	}

	err = s.bgpServer.StopBgp(context.Background(), &bgpapi.StopBgpRequest{})
	if err != nil {
		s.log.Errorf("failed to stop BGP server:", err)
	}
	s.log.Infof("Routing server stopped")
	return nil
}

func (s *Server) ipamUpdateHandler(pool *calicov3.IPPool, prevPool *calicov3.IPPool) error {
	s.log.Debugf("Pool %s updated, handler called", pool.Spec.CIDR)
	// TODO check if we need to change any routes based on VXLAN / IPIPMode config changes
	if prevPool != nil {
		return fmt.Errorf("IPPool updates not supported at this time: old: %+v new: %+v", prevPool, pool)
	}
	return nil
}

func (s *Server) getDefaultBGPConfig() (*calicov3.BGPConfigurationSpec, error) {
	b := true
	conf, err := s.clientv3.BGPConfigurations().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// Fill in nil values with default ones
		if conf.Spec.NodeToNodeMeshEnabled == nil {
			conf.Spec.NodeToNodeMeshEnabled = &b // Go is great sometimes
		}
		if conf.Spec.ASNumber == nil {
			asn, err := numorstring.ASNumberFromString("64512")
			if err != nil {
				return nil, err
			}
			conf.Spec.ASNumber = &asn
		}
		return &conf.Spec, nil
	}
	switch err.(type) {
	case calicoerr.ErrorResourceDoesNotExist:
		s.log.Debug("No default BGP config found, using default options")
		ret := &calicov3.BGPConfigurationSpec{
			LogSeverityScreen:     "INFO",
			NodeToNodeMeshEnabled: &b,
		}
		asn, err := numorstring.ASNumberFromString("64512")
		if err != nil {
			return nil, err
		}
		ret.ASNumber = &asn
		return ret, nil
	default:
		return nil, err
	}
}

func (s *Server) getNodeASN() (*numorstring.ASNumber, error) {
	return s.getPeerASN(config.NodeName)
}

func (s *Server) getPeerASN(host string) (*numorstring.ASNumber, error) {
	node, err := s.clientv3.Nodes().Get(context.Background(), host, options.GetOptions{})
	if err != nil {
		return nil, err
	}
	if node.Spec.BGP == nil {
		return nil, fmt.Errorf("host %s is running in policy-only mode")
	}
	asn := node.Spec.BGP.ASNumber
	if asn == nil {
		return s.defaultBGPConf.ASNumber, nil
	}
	return asn, nil

}

func (s *Server) getGlobalConfig() (*bgpapi.Global, error) {
	var routerId string
	asn, err := s.getNodeASN()
	if err != nil {
		return nil, errors.Wrap(err, "error getting current node AS number")
	}
	if s.hasV4 {
		routerId = s.ipv4.String()
	} else if s.hasV6 {
		routerId = s.ipv6.String()
	} else {
		return nil, errors.Wrap(err, "Cannot make routerId out of IP")
	}
	return &bgpapi.Global{
		As:       uint32(*asn),
		RouterId: routerId,
	}, nil
}

func (s *Server) makePath(prefix string, isWithdrawal bool) (*bgpapi.Path, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	p := ipNet.IP
	masklen, _ := ipNet.Mask.Size()
	v4 := true
	if p.To4() == nil {
		v4 = false
	}

	nlri, err := ptypes.MarshalAny(&bgpapi.IPAddressPrefix{
		Prefix:    p.String(),
		PrefixLen: uint32(masklen),
	})
	if err != nil {
		return nil, err
	}
	var family *bgpapi.Family
	originAttr, err := ptypes.MarshalAny(&bgpapi.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	attrs := []*any.Any{originAttr}

	if v4 {
		family = &bgpFamilyUnicastIPv4
		nhAttr, err := ptypes.MarshalAny(&bgpapi.NextHopAttribute{
			NextHop: s.ipv4.String(),
		})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nhAttr)
	} else {
		family = &bgpFamilyUnicastIPv6
		nlriAttr, err := ptypes.MarshalAny(&bgpapi.MpReachNLRIAttribute{
			NextHops: []string{s.ipv6.String()},
			Nlris:    []*any.Any{nlri},
			Family: &bgpapi.Family{
				Afi:  bgpapi.Family_AFI_IP6,
				Safi: bgpapi.Family_SAFI_UNICAST,
			},
		})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nlriAttr)
	}

	return &bgpapi.Path{
		Nlri:       nlri,
		IsWithdraw: isWithdrawal,
		Pattrs:     attrs,
		Age:        ptypes.TimestampNow(),
		Family:     family,
	}, nil
}

func (s *Server) cleanUpRoutes() error {
	s.log.Tracef("Clean up injected routes")
	filter := &netlink.Route{
		Protocol: RTPROT_GOBGP,
	}
	list4, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	list6, err := netlink.RouteListFiltered(netlink.FAMILY_V6, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	for _, route := range append(list4, list6...) {
		netlink.RouteDel(&route)
	}
	return nil
}

func (s *Server) announceLocalAddress(addr *net.IPNet) error {
	s.log.Debugf("Announcing prefix %s in BGP", addr.String())
	path, err := s.makePath(addr.String(), false)
	if err != nil {
		return errors.Wrap(err, "error making path to announce")
	}
	s.localAddressMap[addr.String()] = addr
	_, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error announcing local address")
}

func (s *Server) withdrawLocalAddress(addr *net.IPNet) error {
	s.log.Debugf("Withdrawing prefix %s from BGP", addr.String())
	path, err := s.makePath(addr.String(), true)
	if err != nil {
		return errors.Wrap(err, "error making path to withdraw")
	}
	delete(s.localAddressMap, addr.String())
	_, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error withdrawing local address")
}

func (s *Server) RestoreLocalAddresses() {
	for _, addr := range s.localAddressMap {
		err := s.announceLocalAddress(addr)
		if err != nil {
			s.log.Errorf("Local address %s restore failed : %+v", addr.String(), err)
		}
	}
}

func (s *Server) AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) {
	var err error
	if isWithdrawal {
		err = s.withdrawLocalAddress(addr)
	} else {
		err = s.announceLocalAddress(addr)
	}
	if err != nil {
		s.log.Errorf("Local address %+v announcing failed : %+v", addr, err)
	}
}

func (s *Server) Serve() {
	for !s.ShouldStop {
		err := s.serveOne()
		if err != nil {
			s.log.Errorf("routing serve returned %v", err)
		}
	}
}

func (s *Server) Stop() {
	s.ShouldStop = true
	s.t.Kill(errors.Errorf("GracefulStop"))
}

func (s *Server) OnVppRestart() {
	s.log.Infof("Restarting ROUTING")
	for _, cn := range s.connectivityMap {
		s.log.Infof("Adding routing : %s", cn.String())
		err := s.updateIPConnectivity(cn, false)
		if err != nil {
			s.log.Errorf("Error re-injecting connectivity %s : %v", cn.String(), err)
		}
	}
}
