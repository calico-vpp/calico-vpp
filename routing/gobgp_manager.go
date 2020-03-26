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
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/calico-vpp/calico-vpp/config"
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
	"gopkg.in/tomb.v2"

	"github.com/calico-vpp/vpplink"
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
	t              tomb.Tomb
	bgpServer      *bgpserver.BgpServer
	client         *calicocli.Client
	clientv3       calicocliv3.Interface
	defaultBGPConf *calicov3.BGPConfigurationSpec
	hasV4          bool
	ipv4           net.IP
	hasV6          bool
	ipv6           net.IP
	nodeName       string
	ipam           IpamCache
	reloadCh       chan string
	prefixReady    chan int
	vpp            *vpplink.VppLink
	l              *logrus.Entry
}

func NewServer(vpp *vpplink.VppLink, l *logrus.Entry) (*Server, error) {
	nodeName := os.Getenv(config.NODENAME)
	calicoCli, err := calicocli.NewFromEnv()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create calico v1 api client")
	}
	calicoCliV3, err := calicocliv3.NewFromEnv()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create calico v3 api client")
	}

	node, err := calicoCliV3.Nodes().Get(context.Background(), nodeName, options.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "cannot fetch current node")
	}

	if node.Spec.BGP == nil {
		return nil, fmt.Errorf("Calico is running in policy-only mode")
	}
	var ipv4, ipv6 net.IP
	var hasV4, hasV6 bool = true, true
	if ipv4, _, err = net.ParseCIDR(node.Spec.BGP.IPv4Address); err != nil {
		hasV4 = false
	}
	if ipv6, _, err = net.ParseCIDR(node.Spec.BGP.IPv6Address); err != nil {
		hasV6 = false
	}

	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize)}
	bgpServer := bgpserver.NewBgpServer(bgpserver.GrpcListenAddress("localhost:50051"), bgpserver.GrpcOption(grpcOpts))

	server := Server{
		bgpServer:   bgpServer,
		client:      calicoCli,
		clientv3:    calicoCliV3,
		nodeName:    nodeName,
		hasV4:       hasV4,
		ipv4:        ipv4,
		hasV6:       hasV6,
		ipv6:        ipv6,
		reloadCh:    make(chan string),
		prefixReady: make(chan int),
		vpp:         vpp,
		l:           l,
	}

	BGPConf, err := server.getDefaultBGPConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error getting default BGP configuration")
	}
	server.defaultBGPConf = BGPConf
	return &server, nil
}

func (s *Server) Serve() {
	s.t.Go(func() error {
		s.bgpServer.Serve()
		return nil
	})

	// bgpAPIServer := bgpapi.NewGrpcServer(s.bgpServer, ":50051")
	// s.t.Go(bgpAPIServer.Serve)

	globalConfig, err := s.getGlobalConfig()
	if err != nil {
		s.l.Fatal("cannot get global configuration: ", err)
	}

	if err := s.bgpServer.StartBgp(context.Background(), &bgpapi.StartBgpRequest{
		Global: globalConfig,
	}); err != nil {
		s.l.Fatal("failed to start BGP server:", err)
	}

	if err := s.initialPolicySetting(); err != nil {
		s.l.Fatal("error configuring initial policies: ", err)
	}

	s.ipam = newIPAMCache(s.l.WithFields(logrus.Fields{"subcomponent": "ipam-cache"}), s.clientv3, s.ipamUpdateHandler)
	// sync IPAM and call ipamUpdateHandler
	s.t.Go(func() error { return fmt.Errorf("syncIPAM: %s", s.ipam.sync()) })
	// watch prefix assigned and announce to other BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchPrefix: %s", s.watchPrefix()) })
	// watch BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchBGPPeers: %s", s.watchBGPPeers()) })
	// watch Nodes
	s.t.Go(func() error { return fmt.Errorf("watchNodes: %s", s.watchNodes()) })

	// TODO need to watch BGP configurations and restart in case of changes
	// Need to get initial BGP config here, pass it to the watchers that need it,
	// and pass its revision to the BGP config and nodes watchers

	// watch routes from other BGP peers and update FIB
	s.t.Go(func() error { return fmt.Errorf("watchBGPPath: %s", s.watchBGPPath()) })

	// watch routes added by kernel and announce to other BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchKernelRoute: %s", s.watchKernelRoute()) })

	ServerRunning <- 1
	<-s.t.Dying()

	if err := s.cleanUpRoutes(); err != nil {
		s.l.Fatalf("%s, also failed to clean up routes which we injected: %s", s.t.Err(), err)
	}
	s.l.Fatal(s.t.Err())

}

func isCrossSubnet(gw net.IP, subnet net.IPNet) bool {
	return !subnet.Contains(gw)
}

func (s *Server) ipamUpdateHandler(pool *calicov3.IPPool, prevPool *calicov3.IPPool) error {
	s.l.Debugf("Pool %s updated, handler called", pool.Spec.CIDR)
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
		s.l.Debug("No \"default\" BGP config found, using default options")
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
	return s.getPeerASN(s.nodeName)
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
	asn, err := s.getNodeASN()
	if err != nil {
		return nil, errors.Wrap(err, "error getting current node AS number")
	}
	return &bgpapi.Global{
		As:       uint32(*asn),
		RouterId: s.ipv4.String(),
	}, nil
}

func (s *Server) isMeshMode() (bool, error) {
	return *s.defaultBGPConf.NodeToNodeMeshEnabled, nil
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

// watchKernelRoute receives netlink route update notification and announces
// kernel/boot routes using BGP.
func (s *Server) watchKernelRoute() error {
	err := s.loadKernelRoute()
	if err != nil {
		return err
	}

	ch := make(chan netlink.RouteUpdate)
	err = netlink.RouteSubscribe(ch, nil)
	if err != nil {
		return err
	}
	for update := range ch {
		s.l.Debugf("kernel update: %s", update)
		if update.Table == syscall.RT_TABLE_MAIN &&
			(update.Protocol == syscall.RTPROT_KERNEL || update.Protocol == syscall.RTPROT_BOOT) {
			// TODO: handle ipPool deletion. RTM_DELROUTE message
			// can belong to previously valid ipPool.
			if s.ipam.match(*update.Dst) == nil {
				continue
			}
			isWithdrawal := false
			switch update.Type {
			case syscall.RTM_DELROUTE:
				isWithdrawal = true
			case syscall.RTM_NEWROUTE:
			default:
				s.l.Debugf("unhandled rtm type: %d", update.Type)
				continue
			}
			path, err := s.makePath(update.Dst.String(), isWithdrawal)
			if err != nil {
				return err
			}
			s.l.Debugf("made path from kernel update: %s", path)
			if _, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Path:      path,
			}); err != nil {
				return err
			}
		} else if update.Table == syscall.RT_TABLE_LOCAL {
			// This means the interface address is updated
			// Some routes we injected may be deleted by the kernel
			// Reload routes from BGP RIB and inject again
			ip, _, _ := net.ParseCIDR(update.Dst.String())
			family := "4"
			if ip.To4() == nil {
				family = "6"
			}
			s.reloadCh <- family
		}
	}
	return fmt.Errorf("netlink route subscription ended")
}

func (s *Server) loadKernelRoute() error {
	<-s.prefixReady
	filter := &netlink.Route{
		Table: syscall.RT_TABLE_MAIN,
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range list {
		if route.Dst == nil {
			continue
		}
		if s.ipam.match(*route.Dst) == nil {
			continue
		}
		if route.Protocol == syscall.RTPROT_KERNEL || route.Protocol == syscall.RTPROT_BOOT {
			path, err := s.makePath(route.Dst.String(), false)
			if err != nil {
				return err
			}
			s.l.Tracef("made path from kernel route: %s", path)
			if _, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Path:      path,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := ptypes.UnmarshalAny(attr, nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := ptypes.UnmarshalAny(attr, mpReachAttr); err == nil {
			if len(mpReachAttr.NextHops) != 1 {
				s.l.Fatalf("Cannot process more than one Nlri in path attributes: %+v", mpReachAttr)
			}
			return mpReachAttr.NextHops[0]
		}
	}
	return ""
}

// injectRoute is a helper function to inject BGP routes to VPP
// TODO: multipath support
func (s *Server) injectRoute(path *bgpapi.Path) error {
	var dst net.IPNet
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	isV4 := false
	otherNodeIP := net.ParseIP(s.getNexthop(path))
	if otherNodeIP == nil {
		return fmt.Errorf("Cannot determine path nexthop: %+v", path)
	}

	if err := ptypes.UnmarshalAny(path.Nlri, ipAddrPrefixNlri); err == nil {
		dst.IP = net.ParseIP(ipAddrPrefixNlri.Prefix)
		if dst.IP == nil {
			return fmt.Errorf("Cannot parse nlri addr: %s", ipAddrPrefixNlri.Prefix)
		} else if dst.IP.To4() == nil {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 128)
		} else {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 32)
			isV4 = true
		}
	} else {
		return fmt.Errorf("Cannot handle Nlri: %+v", path.Nlri)
	}

	return s.AddIPConnectivity(dst, otherNodeIP, isV4, path.IsWithdraw)
}

// watchBGPPath watches BGP routes from other peers and inject them into
// linux kernel
// TODO: multipath support
func (s *Server) watchBGPPath() error {
	var err error
	startMonitor := func(f *bgpapi.Family) (context.CancelFunc, error) {
		ctx, stopFunc := context.WithCancel(context.Background())
		err := s.bgpServer.MonitorTable(
			ctx,
			&bgpapi.MonitorTableRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Name:      "",
				Family:    f,
				Current:   false,
			},
			func(path *bgpapi.Path) {
				if path == nil {
					s.l.Warnf("nil path update, skipping")
					return
				}
				s.l.Infof("Got path update from %s as %d", path.SourceId, path.SourceAsn)
				if path.NeighborIp == "<nil>" { // Weird GoBGP API behaviour
					s.l.Debugf("Ignoring internal path")
					return
				}
				if err := s.injectRoute(path); err != nil {
					s.l.Errorf("cannot inject route: %v", err)
				}
			},
		)
		return stopFunc, err
	}

	var stopV4Monitor, stopV6Monitor context.CancelFunc
	if s.hasV4 {
		stopV4Monitor, err = startMonitor(&bgpFamilyUnicastIPv4)
		if err != nil {
			return errors.Wrap(err, "error starting v4 path monitor")
		}
	}
	if s.hasV6 {
		stopV6Monitor, err = startMonitor(&bgpFamilyUnicastIPv4)
		if err != nil {
			return errors.Wrap(err, "error starting v6 path monitor")
		}
	}
	for family := range s.reloadCh {
		if s.hasV4 && family == "4" {
			stopV4Monitor()
			stopV4Monitor, err = startMonitor(&bgpFamilyUnicastIPv4)
			if err != nil {
				return err
			}
		} else if s.hasV6 && family == "6" {
			stopV6Monitor()
			stopV6Monitor, err = startMonitor(&bgpFamilyUnicastIPv6)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// initialPolicySetting initialize BGP export policy.
// this creates two prefix-sets named 'aggregated' and 'host'.
// A route is allowed to be exported when it matches with 'aggregated' set,
// and not allowed when it matches with 'host' set.
func (s *Server) initialPolicySetting() error {
	createEmptyPrefixSet := func(name string) error {
		ps := &bgpapi.DefinedSet{
			DefinedType: bgpapi.DefinedType_PREFIX,
			Name:        name,
		}
		return s.bgpServer.AddDefinedSet(context.Background(), &bgpapi.AddDefinedSetRequest{DefinedSet: ps})
	}
	for _, name := range []string{aggregatedPrefixSetName, hostPrefixSetName} {
		if err := createEmptyPrefixSet(name); err != nil {
			return errors.Wrapf(err, "error creating prefix set %s", name)
		}
	}
	// intended to work as same as 'calico_pools' export filter of BIRD configuration
	definition := &bgpapi.Policy{
		Name: "calico_aggr",
		Statements: []*bgpapi.Statement{
			&bgpapi.Statement{
				Conditions: &bgpapi.Conditions{
					PrefixSet: &bgpapi.MatchSet{
						MatchType: bgpapi.MatchType_ANY,
						Name:      aggregatedPrefixSetName,
					},
				},
				Actions: &bgpapi.Actions{
					RouteAction: bgpapi.RouteAction_ACCEPT,
				},
			},
			&bgpapi.Statement{
				Conditions: &bgpapi.Conditions{
					PrefixSet: &bgpapi.MatchSet{
						MatchType: bgpapi.MatchType_ANY,
						Name:      hostPrefixSetName,
					},
				},
				Actions: &bgpapi.Actions{
					RouteAction: bgpapi.RouteAction_REJECT,
				},
			},
		},
	}

	if err := s.bgpServer.AddPolicy(context.Background(), &bgpapi.AddPolicyRequest{
		Policy:                  definition,
		ReferExistingStatements: false},
	); err != nil {
		return errors.Wrap(err, "error adding policy")
	}
	err := s.bgpServer.AddPolicyAssignment(context.Background(), &bgpapi.AddPolicyAssignmentRequest{
		Assignment: &bgpapi.PolicyAssignment{
			Name:      "global",
			Direction: bgpapi.PolicyDirection_EXPORT,
			Policies: []*bgpapi.Policy{
				definition,
			},
			DefaultAction: bgpapi.RouteAction_ACCEPT,
		},
	})
	return errors.Wrap(err, "cannot add policy assignment")
}

// TODO rename this
func (s *Server) updatePrefixSet(paths []*bgpapi.Path) error {
	for _, path := range paths {
		err := s._updatePrefixSet(path)
		if err != nil {
			return errors.Wrapf(err, "error processing path %+v", path)
		}
	}
	return nil
}

// _updatePrefixSet updates 'aggregated' and 'host' prefix-sets
// we add the exact prefix to 'aggregated' set, and add corresponding longer
// prefixes to 'host' set.
//
// e.g. prefix: "192.168.1.0/26" del: false
//      add "192.168.1.0/26"     to 'aggregated' set
//      add "192.168.1.0/26..32" to 'host'       set
//
func (s *Server) _updatePrefixSet(path *bgpapi.Path) error {
	s.l.Infof("Updating local prefix set with %+v", path)
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	var prefixAddr string = ""
	var prefixLen uint32 = 0xffff
	var err error = nil
	if err := ptypes.UnmarshalAny(path.Nlri, ipAddrPrefixNlri); err == nil {
		prefixAddr = ipAddrPrefixNlri.Prefix
		prefixLen = ipAddrPrefixNlri.PrefixLen
	} else {
		return fmt.Errorf("Cannot handle Nlri: %+v", path.Nlri)
	}
	del := path.IsWithdraw
	prefix := prefixAddr + "/" + strconv.FormatUint(uint64(prefixLen), 10)
	// Add path to aggregated prefix set, allowing to export it
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        aggregatedPrefixSetName,
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix:      prefix,
				MaskLengthMin: prefixLen,
				MaskLengthMax: prefixLen,
			},
		},
	}
	if del {
		err = s.bgpServer.DeleteDefinedSet(
			context.Background(),
			&bgpapi.DeleteDefinedSetRequest{DefinedSet: ps, All: false},
		)
	} else {
		err = s.bgpServer.AddDefinedSet(
			context.Background(),
			&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
		)
	}
	if err != nil {
		return errors.Wrapf(err, "error adding / deleting defined set %+v", ps)
	}
	// Add all contained prefixes to host prefix set, forbidding the export of containers /32s or /128s
	max := uint32(32)
	if strings.Contains(prefixAddr, ":") {
		s.l.Debugf("Address %s detected as v6", prefixAddr)
		max = 128
	}
	ps = &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        hostPrefixSetName,
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix:      prefix,
				MaskLengthMax: max,
				MaskLengthMin: prefixLen,
			},
		},
	}
	if del {
		err = s.bgpServer.DeleteDefinedSet(
			context.Background(),
			&bgpapi.DeleteDefinedSetRequest{DefinedSet: ps, All: false},
		)
	} else {
		err = s.bgpServer.AddDefinedSet(
			context.Background(),
			&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
		)
	}
	if err != nil {
		return errors.Wrapf(err, "error adding / deleting defined set %+v", ps)
	}

	// Finally add/remove path to/from the main table to annouce it to our peers
	if del {
		err = s.bgpServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
			TableType: bgpapi.TableType_GLOBAL,
			Path:      path,
		})
	} else {
		_, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
			TableType: bgpapi.TableType_GLOBAL,
			Path:      path,
		})
	}

	return errors.Wrapf(err, "error adding / deleting path %+v", path)
}

func (s *Server) cleanUpRoutes() error {
	s.l.Tracef("Clean up injected routes")
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

func (s *Server) announceLocalAddress(addr net.IPNet) error {
	s.l.Debugf("Announcing prefix %s in BGP", addr.String())
	path, err := s.makePath(addr.String(), false)
	if err != nil {
		return errors.Wrap(err, "error making path to announce")
	}
	_, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error announcing local address")
}

func (s *Server) withdrawLocalAddress(addr net.IPNet) error {
	s.l.Debugf("Withdrawing prefix %s from BGP", addr.String())
	path, err := s.makePath(addr.String(), true)
	if err != nil {
		return errors.Wrap(err, "error making path to withdraw")
	}
	_, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
		TableType: bgpapi.TableType_GLOBAL,
		Path:      path,
	})
	return errors.Wrap(err, "error withdrawing local address")
}

func AnnounceLocalAddress(addr net.IPNet) error {
	// Sync done by routing.ServerRunning
	return server.announceLocalAddress(addr)
}

func WithdrawLocalAddress(addr net.IPNet) error {
	// Sync done by routing.ServerRunning
	return server.withdrawLocalAddress(addr)
}

func Run(vpp *vpplink.VppLink, l *logrus.Entry) {
	rawloglevel := os.Getenv("CALICO_BGP_LOGSEVERITYSCREEN")
	if rawloglevel != "" {
		loglevel, err := logrus.ParseLevel(rawloglevel)
		if err != nil {
			l.WithError(err).Error("Failed to parse BGP loglevel: %s, defaulting to info", rawloglevel)
		} else {
			l.Infof("Setting BGP log level to %s", rawloglevel)
			logrus.SetLevel(loglevel) // This sets the log level for the GoBGP server
			// This is separate from the level used by the logger in this package
		}
	}

	_server, err := NewServer(vpp, l)
	if err != nil {
		l.Errorf("failed to create new server")
		l.Fatal(err)
	}
	server = _server
	server.Serve()
}

func GracefulStop() {
	server.t.Kill(errors.Errorf("GracefulStop"))
}
