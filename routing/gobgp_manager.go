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

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	bgpapi "github.com/osrg/gobgp/api"
	bgpserver "github.com/osrg/gobgp/pkg/server"
	"github.com/pkg/errors"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v1"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	backendapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	calicocliv3 "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"
)

// TODO: switch as much as possible to clientv3

const (
	NODENAME = "NODENAME"

	aggregatedPrefixSetName = "aggregated"
	hostPrefixSetName       = "host"

	RTPROT_GOBGP = 0x11
)

var (
	bgpFamilyUnicastIPv4 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP, Safi: bgpapi.Family_SAFI_UNICAST}
	bgpFamilyUnicastIPv6 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_UNICAST}
)

type IpamCache interface {
	match(string) *model.IPPool
	update(*model.KVPair, bool) error
	sync() error
}

// VERSION is filled out during the build process (using git describe output)
var VERSION string

// recursiveNexthopLookup returns bgpNexthop's actual nexthop
// In GCE environment, the interface address is /32 and the BGP nexthop is
// off-subnet. This function looks up kernel RIB and returns a nexthop to
// reach the BGP nexthop.
// When the BGP nexthop can be reached with a connected route,
// this function returns the BGP nexthop.
func recursiveNexthopLookup(bgpNexthop net.IP) (net.IP, error) {
	routes, err := netlink.RouteGet(bgpNexthop)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no route for path: %s", bgpNexthop)
	}
	r := routes[0]
	if r.Gw != nil {
		return r.Gw, nil
	}
	// bgpNexthop can be reached by a connected route
	return bgpNexthop, nil
}

func cleanUpRoutes() error {
	log.Println("Clean up injected routes")
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

type Server struct {
	t           tomb.Tomb
	bgpServer   *bgpserver.BgpServer
	client      *calicocli.Client
	clientv3    calicocliv3.Interface
	hasV4       bool
	ipv4        net.IP
	hasV6       bool
	ipv6        net.IP
	nodeName    string
	ipam        IpamCache
	reloadCh    chan string
	prefixReady chan int
}

func NewServer() (*Server, error) {
	nodeName := os.Getenv(NODENAME)
	calicoCli, err := calicocli.NewFromEnv()
	if err != nil {
		return nil, err
	}
	calicoCliV3, err := calicocliv3.NewFromEnv()
	if err != nil {
		return nil, err
	}

	node, err := calicoCliV3.Nodes().Get(context.Background(), nodeName, options.GetOptions{})
	if err != nil {
		return nil, err
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

	bgpServer := bgpserver.NewBgpServer()

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
	}
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
		log.Fatal(err)
	}

	if err := s.bgpServer.StartBgp(context.Background(), &bgpapi.StartBgpRequest{
		Global: globalConfig,
	}); err != nil {
		log.Fatal("failed to start BGP server:", err)
	}

	if err := s.initialPolicySetting(); err != nil {
		log.Fatal(err)
	}

	s.ipam = newIPAMCache(s.client, s.ipamUpdateHandler)
	// sync IPAM and call ipamUpdateHandler
	s.t.Go(func() error { return fmt.Errorf("syncIPAM: %s", s.ipam.sync()) })
	// watch prefix assigned and announce to other BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchPrefix: %s", s.watchPrefix()) })
	// watch BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchBGPPeers: %s", s.watchBGPPeers()) })
	// watch Nodes
	s.t.Go(func() error { return fmt.Errorf("watchNodes: %s", s.watchNodes()) })

	// TODO need to watch global ASN and mesh settings?

	////

	// watch routes from other BGP peers and update FIB
	s.t.Go(func() error { return fmt.Errorf("watchBGPPath: %s", s.watchBGPPath()) })

	// watch routes added by kernel and announce to other BGP peers
	s.t.Go(func() error { return fmt.Errorf("watchKernelRoute: %s", s.watchKernelRoute()) })

	<-s.t.Dying()

	if err := cleanUpRoutes(); err != nil {
		log.Fatalf("%s, also failed to clean up routes which we injected: %s", s.t.Err(), err)
	}
	log.Fatal(s.t.Err())

}

func isCrossSubnet(gw net.IP, subnet net.IPNet) bool {
	return !subnet.Contains(gw)
}

func (s *Server) ipamUpdateHandler(pool *model.IPPool) error {
	filter := &netlink.Route{
		Protocol: RTPROT_GOBGP,
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	node, err := s.client.Nodes().Get(calicoapi.NodeMetadata{Name: s.nodeName})
	if err != nil {
		return err
	}

	for _, route := range list {
		if route.Dst == nil {
			continue
		}
		prefix := route.Dst.String()
		inPool, err := contains(pool, prefix)
		if err != nil {
			return err
		}
		if inPool {
			ipip := pool.IPIPMode != encap.Undefined
			if pool.IPIPMode == encap.CrossSubnet && !isCrossSubnet(route.Gw, node.Spec.BGP.IPv4Address.Network().IPNet) {
				ipip = false
			}
			if ipip {
				i, err := net.InterfaceByName(pool.IPIPInterface)
				if err != nil {
					return err
				}
				route.LinkIndex = i.Index
				route.SetFlag(netlink.FLAG_ONLINK)
			} else {
				log.Println("listing paths")
				err := s.bgpServer.ListPath(
					context.Background(),
					&bgpapi.ListPathRequest{
						TableType: bgpapi.TableType_GLOBAL,
						Name:      "",
						Family:    &bgpFamilyUnicastIPv4,
						Prefixes: []*bgpapi.TableLookupPrefix{
							&bgpapi.TableLookupPrefix{
								Prefix: prefix,
							},
						},
					},
					func(destination *bgpapi.Destination) {
						log.Println("Got destination for prefix %s: %+v", prefix, destination)
					},
				)
				if err != nil {
					return errors.Wrap(err, "error listing paths")
				}

				// var best *bgpapi.Path = nil
				// for _, p := range dest.Paths {
				// 	if p.Best && (best == nil || p)
				// }
				// if len(bests) == 0 {
				// 	log.Printf("no best for %s", prefix)
				// 	continue
				// }
				// best := bests[0]
				// if best.IsLocal() {
				// 	log.Printf("%s's best is local path", prefix)
				// 	continue
				// }
				// gw, err := recursiveNexthopLookup(best.GetNexthop())
				// if err != nil {
				// 	return err
				// }
				// route.Gw = gw
				// route.Flags = 0
				// rs, err := netlink.RouteGet(gw)
				// if err != nil {
				// 	return err
				// }
				// if len(rs) == 0 {
				// 	return fmt.Errorf("no route for path: %s", gw)
				// }
				// r := rs[0]
				// route.LinkIndex = r.LinkIndex
			}
			return netlink.RouteReplace(&route)
		}
	}
	return nil
}

func (s *Server) getNodeASN() (numorstring.ASNumber, error) {
	return s.getPeerASN(s.nodeName)
}

func (s *Server) getPeerASN(host string) (numorstring.ASNumber, error) {
	node, err := s.clientv3.Nodes().Get(context.Background(), host, options.GetOptions{})
	if err != nil {
		return 0, err
	}
	if node.Spec.BGP == nil {
		return 0, fmt.Errorf("host %s is running in policy-only mode")
	}
	asn := node.Spec.BGP.ASNumber
	if asn == nil {
		return s.client.Config().GetGlobalASNumber()
	}
	return *asn, nil

}

func (s *Server) getGlobalConfig() (*bgpapi.Global, error) {
	asn, err := s.getNodeASN()
	if err != nil {
		return nil, err
	}
	return &bgpapi.Global{
		As:       uint32(asn),
		RouterId: s.ipv4.String(),
	}, nil
}

func (s *Server) isMeshMode() (bool, error) {
	return s.client.Config().GetNodeToNodeMesh()
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

// getAssignedPrefixes retrives prefixes assigned to the node and returns them as a
// list of BGP path.
// using backend directly since libcalico-go doesn't seem to have a method to return
// assigned prefixes yet.
func (s *Server) getAssignedPrefixes() ([]*bgpapi.Path, string, error) {
	var ps []*bgpapi.Path
	revision := ""

	f := func(ipVersion int) error {
		blockList, err := s.client.Backend.List(
			context.Background(),
			model.BlockAffinityListOptions{Host: os.Getenv(NODENAME), IPVersion: ipVersion},
			revision,
		)
		if err != nil {
			return err
		}
		if revision == "" {
			revision = blockList.Revision
		}
		for _, block := range blockList.KVPairs {
			key := block.Key.(model.BlockAffinityKey)
			// value := block.Value.(model.BlockAffinity)
			path, err := s.makePath(key.CIDR.String(), false)
			if err != nil {
				return err
			}
			ps = append(ps, path)
		}
		return nil
	}

	if s.ipv4 != nil {
		if err := f(4); err != nil {
			return nil, "", err
		}
	}
	if s.ipv6 != nil {
		if err := f(6); err != nil {
			return nil, "", err
		}
	}
	return ps, revision, nil
}

// watchPrefix watches etcd /calico/ipam/v2/host/$NODENAME and add/delete
// aggregated routes which are assigned to the node.
// This function also updates policy appropriately.
func (s *Server) watchPrefix() error {
	paths, revision, err := s.getAssignedPrefixes()
	if err != nil {
		return err
	}
	if err = s.updatePrefixSet(paths); err != nil {
		return err
	}
	s.prefixReady <- 1

	prefixWatcher, err := s.client.Backend.Watch(
		context.Background(),
		model.BlockAffinityListOptions{Host: os.Getenv(NODENAME)},
		revision,
	)
	if err != nil {
		return err
	}

	for update := range prefixWatcher.ResultChan() {
		del := false
		pair := update.New
		switch update.Type {
		case backendapi.WatchError:
			return update.Error
		case backendapi.WatchDeleted:
			del = true
			pair = update.Old
		case backendapi.WatchAdded, backendapi.WatchModified:
		}
		key := pair.Key.(model.BlockAffinityKey)
		path, err := s.makePath(key.CIDR.String(), del)
		if err != nil {
			return err
		}
		if err = s.updatePrefixSet([]*bgpapi.Path{path}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) createBGPPeer(ip string, asn uint32) (*bgpapi.Peer, error) {
	ipAddr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil, err
	}
	typ := &bgpFamilyUnicastIPv4
	if ipAddr.IP.To4() == nil {
		typ = &bgpFamilyUnicastIPv6
	}

	afiSafis := []*bgpapi.AfiSafi{
		&bgpapi.AfiSafi{
			Config: &bgpapi.AfiSafiConfig{
				Family:  typ,
				Enabled: true,
			},
			MpGracefulRestart: &bgpapi.MpGracefulRestart{
				Config: &bgpapi.MpGracefulRestartConfig{
					Enabled: true,
				},
			},
		},
	}
	peer := &bgpapi.Peer{
		Conf: &bgpapi.PeerConf{
			NeighborAddress: ipAddr.String(),
			PeerAs:          asn,
		},
		GracefulRestart: &bgpapi.GracefulRestart{
			Enabled:             true,
			RestartTime:         120,
			LonglivedEnabled:    true,
			NotificationEnabled: true,
		},
		AfiSafis: afiSafis,
	}
	return peer, nil
}

func (s *Server) addBGPPeer(ip string, asn uint32) error {
	peer, err := s.createBGPPeer(ip, asn)
	if err != nil {
		return err
	}
	err = s.bgpServer.AddPeer(context.Background(), &bgpapi.AddPeerRequest{Peer: peer})
	return err
}

func (s *Server) updateBGPPeer(ip string, asn uint32) error {
	peer, err := s.createBGPPeer(ip, asn)
	if err != nil {
		return err
	}
	_, err = s.bgpServer.UpdatePeer(context.Background(), &bgpapi.UpdatePeerRequest{Peer: peer})
	return err
}

func (s *Server) deleteBGPPeer(ip string) error {
	err := s.bgpServer.DeletePeer(context.Background(), &bgpapi.DeletePeerRequest{Address: ip})
	return err
}

func (s *Server) handlePeerUpdate(peer *calicov3.BGPPeer, eventType watch.EventType) error {
	log.Debugf("Got peer update: %s %+v", eventType, peer)
	// First check if we should peer with this peer at all
	if peer.Spec.Node != "" && peer.Spec.Node != s.nodeName {
		return nil
	}
	// TODO handle NodeSelector / PeerSelector (how?)
	switch eventType {
	case watch.Error:
	case watch.Added:
		s.addBGPPeer(peer.Spec.PeerIP, uint32(peer.Spec.ASNumber))
	case watch.Modified:
		s.updateBGPPeer(peer.Spec.PeerIP, uint32(peer.Spec.ASNumber))
	case watch.Deleted:
		s.deleteBGPPeer(peer.Spec.PeerIP)
	}
	return nil
}

func (s *Server) watchBGPPeers() error {
	peers, err := s.clientv3.BGPPeers().List(context.Background(), options.ListOptions{})
	if err != nil {
		return err
	}
	for _, peer := range peers.Items {
		s.handlePeerUpdate(&peer, watch.Added)
	}

	watcher, err := s.clientv3.BGPPeers().Watch(context.Background(), options.ListOptions{ResourceVersion: peers.ResourceVersion})
	if err != nil {
		return err
	}
	for update := range watcher.ResultChan() {
		peer := update.Object
		switch update.Type {
		case watch.Added, watch.Modified:
		case watch.Deleted:
			peer = update.Previous
		case watch.Error:
			return update.Error
		}
		s.handlePeerUpdate(peer.(*calicov3.BGPPeer), update.Type)
	}
	return nil
}

// Returns true if the config of the current node has changed and requires a restart
func (s *Server) handleNodeUpdate(node *calicov3.Node, eventType watch.EventType, isMesh bool) (bool, error) {
	log.Debugf("Got node update: mesh:%s %s %+v", isMesh, eventType, node)
	// If the mesh is disabled, discard all updates that aren't on the current node
	if len(node.Spec.OrchRefs) != 1 {
		return true, fmt.Errorf("%d OrchRefs found in node, cannot continue", len(node.Spec.OrchRefs))
	}
	if node.Spec.OrchRefs[0].NodeName == s.nodeName {
		// No need to manage ourselves, but if we change we need to restart and reconfigure
		return true, nil
	}
	if !isMesh || node.Spec.BGP == nil { // No BGP config for this node
		return false, nil
	}
	var asNumber uint32
	var err error
	if node.Spec.BGP.ASNumber == nil {
		asn, err := s.client.Config().GetGlobalASNumber() // TODO: cache this?
		asNumber = uint32(asn)
		if err != nil {
			return false, err
		}
	} else {
		asNumber = uint32(*node.Spec.BGP.ASNumber)
	}
	v4IP, _, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
	if err != nil {
		return false, nil
	}
	v6Set := node.Spec.BGP.IPv6Address != ""
	var v6IP net.IP
	if v6Set {
		v6IP, _, err = net.ParseCIDR(node.Spec.BGP.IPv6Address)
		if err != nil {
			return false, err
		}
	}
	switch eventType {
	case watch.Error:
	case watch.Added:
		s.addBGPPeer(v4IP.String(), asNumber) // v4 seems to be mandatory
		if v6Set {
			s.addBGPPeer(v6IP.String(), asNumber)
		}
	case watch.Modified:
		// TODO this doesn't work if the IP address changes
		// need to get the old node and delete the corresponding peer in that case
		s.updateBGPPeer(v4IP.String(), asNumber)
		if v6Set {
			s.updateBGPPeer(v6IP.String(), asNumber)
		}
	case watch.Deleted:
		s.deleteBGPPeer(v4IP.String())
		if v6Set {
			s.deleteBGPPeer(v6IP.String())
		}
	}
	return false, nil
}

func (s *Server) watchNodes() error {
	isMesh, err := s.isMeshMode()
	if err != nil {
		return err
	}
	// TODO: Get and watch only ourselves if there is no mesh
	nodes, err := s.clientv3.Nodes().List(context.Background(), options.ListOptions{})
	if err != nil {
		return err
	}
	for _, node := range nodes.Items {
		s.handleNodeUpdate(&node, watch.Added, isMesh)
	}

	watcher, err := s.clientv3.Nodes().Watch(context.Background(), options.ListOptions{ResourceVersion: nodes.ResourceVersion})
	if err != nil {
		return err
	}
	for update := range watcher.ResultChan() {
		node := update.Object
		switch update.Type {
		case watch.Added, watch.Modified:
		case watch.Deleted:
			node = update.Previous
		case watch.Error:
			return update.Error
		}
		s.handleNodeUpdate(node.(*calicov3.Node), update.Type, isMesh)
	}
	return nil
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
		log.Printf("kernel update: %s", update)
		if update.Table == syscall.RT_TABLE_MAIN &&
			(update.Protocol == syscall.RTPROT_KERNEL || update.Protocol == syscall.RTPROT_BOOT) {
			// TODO: handle ipPool deletion. RTM_DELROUTE message
			// can belong to previously valid ipPool.
			if s.ipam.match(update.Dst.String()) == nil {
				continue
			}
			isWithdrawal := false
			switch update.Type {
			case syscall.RTM_DELROUTE:
				isWithdrawal = true
			case syscall.RTM_NEWROUTE:
			default:
				log.Printf("unhandled rtm type: %d", update.Type)
				continue
			}
			path, err := s.makePath(update.Dst.String(), isWithdrawal)
			if err != nil {
				return err
			}
			log.Printf("made path from kernel update: %s", path)
			if _, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
				TableType: bgpapi.TableType_GLOBAL,
				VrfId:     "",
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
		if s.ipam.match(route.Dst.String()) == nil {
			continue
		}
		if route.Protocol == syscall.RTPROT_KERNEL || route.Protocol == syscall.RTPROT_BOOT {
			path, err := s.makePath(route.Dst.String(), false)
			if err != nil {
				return err
			}
			log.Printf("made path from kernel route: %s", path)
			if _, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
				TableType: bgpapi.TableType_GLOBAL,
				VrfId:     "",
				Path:      path,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := ptypes.UnmarshalAny(attr, nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := ptypes.UnmarshalAny(attr, mpReachAttr); err == nil {
			if len(mpReachAttr.NextHops) != 1 {
				log.Fatalf("Cannot process more than one Nlri in path attributes: %+v", mpReachAttr)
			}
			return mpReachAttr.NextHops[0]
		}
	}
	return ""
}

// injectRoute is a helper function to inject BGP routes to linux kernel
// TODO: multipath support
func (s *Server) injectRoute(path *bgpapi.Path) error {
	nexthopAddr := getNexthop(path)
	nexthop := net.ParseIP(nexthopAddr)
	if nexthop == nil {
		return fmt.Errorf("Cannot determine path nexthop: %+v", path)
	}
	nlri := path.GetNlri()
	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst:      dst,
		Gw:       nexthop,
		Protocol: RTPROT_GOBGP,
	}

	ipip := false
	if dst.IP.To4() != nil {
		if p := s.ipam.match(nlri.String()); p != nil {
			ipip = p.IPIPMode != encap.Undefined

			node, err := s.client.Nodes().Get(calicoapi.NodeMetadata{Name: s.nodeName})
			if err != nil {
				return err
			}

			if p.IPIPMode == encap.CrossSubnet && !isCrossSubnet(route.Gw, node.Spec.BGP.IPv4Address.Network().IPNet) {
				ipip = false
			}
			if ipip {
				i, err := net.InterfaceByName(p.IPIPInterface)
				if err != nil {
					return err
				}
				route.LinkIndex = i.Index
				route.SetFlag(netlink.FLAG_ONLINK)
			}
		}
		// TODO: if !IsWithdraw, we'd ignore that
	}

	if path.IsWithdraw {
		log.Printf("removed route %s from VPP", nlri)
		return netlink.RouteDel(route)
	}
	if !ipip {
		gw, err := recursiveNexthopLookup(nexthop)
		if err != nil {
			return err
		}
		route.Gw = gw
	}
	log.Printf("added route %s to kernel %s", nlri, route)
	return netlink.RouteReplace(route)
}

// watchBGPPath watches BGP routes from other peers and inject them into
// linux kernel
// TODO: multipath support
func (s *Server) watchBGPPath() error {
	var err error
	startMonitor := func(f *bgpapi.Family) (context.CancelFunc, error) {
		ctx, stopFunc := context.WithCancel(nil)
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
					log.Warnf("nil path update, skipping")
					return
				}
				log.Infof("Got path update: %+v", path)
				if !path.IsFromExternal {
					log.Debugf("Ignoring internal path")
					return
				}
				if err := s.injectRoute(path); err != nil {
					fmt.Errorf("cannot inject route: %v", err)
				}
			},
		)
		return stopFunc, err
	}

	var stopV4Monitor, stopV6Monitor context.CancelFunc
	if s.hasV4 {
		stopV4Monitor, err = startMonitor(&bgpFamilyUnicastIPv4)
		if err != nil {
			return err
		}
	}
	if s.hasV6 {
		stopV6Monitor, err = startMonitor(&bgpFamilyUnicastIPv4)
		if err != nil {
			return err
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
			return err
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
		return err
	}
	return s.bgpServer.AddPolicyAssignment(context.Background(), &bgpapi.AddPolicyAssignmentRequest{
		Assignment: &bgpapi.PolicyAssignment{
			Name:      "",
			Direction: bgpapi.PolicyDirection_EXPORT,
			Policies: []*bgpapi.Policy{
				definition,
			},
			DefaultAction: bgpapi.RouteAction_ACCEPT,
		},
	})
}

// TODO rename this
func (s *Server) updatePrefixSet(paths []*bgpapi.Path) error {
	for _, path := range paths {
		err := s._updatePrefixSet(path)
		if err != nil {
			return err
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
	prefix := path.GetNlri().String()
	del := path.IsWithdraw
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}
	// Add/remove path to aggregated prefix set, allowing to export it
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        aggregatedPrefixSetName,
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix: prefix,
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
		return err
	}
	// Add/remove all contained prefixes to host prefix set, forbidding the export of containers /32s or /128s
	min, _ := ipNet.Mask.Size()
	max := 32
	if ipNet.IP.To4() == nil {
		max = 128
	}
	ps = &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        hostPrefixSetName,
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix:      prefix,
				MaskLengthMax: uint32(max),
				MaskLengthMin: uint32(min),
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
		return err
	}

	// Finally add/remove path to/from the main table to annouce it to our peers
	if del {
		err = s.bgpServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
			TableType: bgpapi.TableType_GLOBAL,
			VrfId:     "",
			Path:      path,
		})
	} else {
		_, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
			TableType: bgpapi.TableType_GLOBAL,
			VrfId:     "",
			Path:      path,
		})
	}

	return err
}

func main() {

	// Display the version on "-v", otherwise just delegate to the skel code.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("Calico", flag.ExitOnError)

	version := flagSet.Bool("v", false, "Display version")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	rawloglevel := os.Getenv("CALICO_BGP_LOGSEVERITYSCREEN")
	loglevel := log.InfoLevel
	if rawloglevel != "" {
		loglevel, err = log.ParseLevel(rawloglevel)
		if err != nil {
			log.WithError(err).Error("Failed to parse loglevel, defaulting to info.")
			loglevel = log.InfoLevel
		}
	}
	log.SetLevel(loglevel)

	server, err := NewServer()
	if err != nil {
		log.Printf("failed to create new server")
		log.Fatal(err)
	}

	server.Serve()
}
