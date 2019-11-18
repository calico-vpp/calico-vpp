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
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/transport"
	bgpapi "github.com/osrg/gobgp/api"
	bgpconfig "github.com/osrg/gobgp/pkg/config"
	bgp "github.com/osrg/gobgp/pkg/packet/bgp"
	bgpserver "github.com/osrg/gobgp/pkg/server"
	calicoapi "github.com/projectcalico/libcalico-go/lib/apis/v1"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	calicoscope "github.com/projectcalico/libcalico-go/lib/scope"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"
)

const (
	NODENAME      = "NODENAME"
	INTERVAL      = "BGPD_INTERVAL"
	AS            = "AS"
	CALICO_PREFIX = "/calico"
	CALICO_BGP    = CALICO_PREFIX + "/bgp/v1"
	CALICO_AGGR   = CALICO_PREFIX + "/ipam/v2/host"
	CALICO_IPAM   = CALICO_PREFIX + "/v1/ipam"

	IpPoolV4       = CALICO_IPAM + "/v4/pool"
	GlobalBGP      = CALICO_BGP + "/global"
	GlobalASN      = GlobalBGP + "/as_num"
	GlobalNodeMesh = GlobalBGP + "/node_mesh"
	GlobalLogging  = GlobalBGP + "/loglevel"
	AllNodes       = CALICO_BGP + "/host"

	PollingInterval    = 300
	defaultDialTimeout = 30 * time.Second

	aggregatedPrefixSetName = "aggregated"
	hostPrefixSetName       = "host"

	RTPROT_GOBGP = 0x11
)

type IpamCache interface {
	match(string) *ipPool
	update(interface{}, bool) error
	sync() error
}

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func underscore(ip string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', ':':
			return '_'
		}
		return r
	}, ip)
}

func errorButKeyNotFound(err error) error {
	if e, ok := err.(etcd.Error); ok && e.Code == etcd.ErrorCodeKeyNotFound {
		return nil
	}
	return err
}

func getEtcdConfig(cfg *calicoapi.CalicoAPIConfig) (etcd.Config, error) {
	var config etcd.Config
	etcdcfg := cfg.Spec.EtcdConfig
	etcdEndpoints := etcdcfg.EtcdEndpoints
	if etcdEndpoints == "" {
		etcdEndpoints = fmt.Sprintf("%s://%s", etcdcfg.EtcdScheme, etcdcfg.EtcdAuthority)
	}
	tls := transport.TLSInfo{
		CAFile:   etcdcfg.EtcdCACertFile,
		CertFile: etcdcfg.EtcdCertFile,
		KeyFile:  etcdcfg.EtcdKeyFile,
	}
	t, err := transport.NewTransport(tls, defaultDialTimeout)
	if err != nil {
		return config, err
	}
	config.Endpoints = strings.Split(etcdEndpoints, ",")
	config.Transport = t
	return config, nil
}

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
	datastore   calicoapi.DatastoreType
	client      *calicocli.Client
	etcd        etcd.KeysAPI
	process     *IntervalProcessor
	ipv4        net.IP
	ipv6        net.IP
	ipam        IpamCache
	reloadCh    chan []*bgptable.Path
	prefixReady chan int
}

func NewServer() (*Server, error) {
	config, err := calicocli.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, err
	}

	calicoCli, err := calicocli.New(*config)
	if err != nil {
		return nil, err
	}

	node, err := calicoCli.Nodes().Get(calicoapi.NodeMetadata{Name: os.Getenv(NODENAME)})
	if err != nil {
		return nil, err
	}

	if node.Spec.BGP == nil {
		return nil, fmt.Errorf("Calico is running in policy-only mode")
	}
	var ipv4, ipv6 net.IP
	if ipnet := node.Spec.BGP.IPv4Address; ipnet != nil {
		ipv4 = ipnet.IP
	}
	if ipnet := node.Spec.BGP.IPv6Address; ipnet != nil {
		ipv6 = ipnet.IP
	}

	bgpServer := bgpserver.NewBgpServer()

	datastoreType := config.Spec.DatastoreType
	server := Server{
		bgpServer:   bgpServer,
		datastore:   datastoreType,
		client:      calicoCli,
		ipv4:        ipv4,
		ipv6:        ipv6,
		reloadCh:    make(chan []*bgptable.Path),
		prefixReady: make(chan int),
	}

	if datastoreType == calicoapi.EtcdV2 {
		etcdConfig, err := getEtcdConfig(config)
		if err != nil {
			return nil, err
		}
		cli, err := etcd.New(etcdConfig)
		if err != nil {
			return nil, err
		}
		server.etcd = etcd.NewKeysAPI(cli)
	} else if datastoreType == calicoapi.Kubernetes {
		k8s, err := NewK8sClient(&server)
		if err != nil {
			return nil, err
		}
		ipam := NewIPAMCacheK8s(&server, server.ipamUpdateHandler)
		server.ipam = ipam
		interval := PollingInterval
		i, err := strconv.Atoi(os.Getenv(INTERVAL))
		if err == nil {
			interval = i
		}
		server.process = &IntervalProcessor{
			interval: interval,
			k8scli:   k8s,
			ipam:     ipam,
		}
	} else {
		log.Fatal("unsupported datastore type: ", datastoreType)
	}

	return &server, nil
}

func (s *Server) Serve() {
	s.t.Go(func() error {
		s.bgpServer.Serve()
		return nil
	})

	bgpAPIServer := bgpapi.NewGrpcServer(s.bgpServer, ":50051")
	s.t.Go(bgpAPIServer.Serve)

	globalConfig, err := s.getGlobalConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := s.bgpServer.Start(globalConfig); err != nil {
		log.Fatal("failed to start BGP server:", err)
	}

	if err := s.initialPolicySetting(); err != nil {
		log.Fatal(err)
	}

	if s.datastore == calicoapi.EtcdV2 {
		s.ipam = newIPAMCache(s.etcd, s.ipamUpdateHandler)
		// sync IPAM and call ipamUpdateHandler
		s.t.Go(func() error { return fmt.Errorf("syncIPAM: %s", s.ipam.sync()) })
		// watch prefix assigned and announce to other BGP peers
		s.t.Go(func() error { return fmt.Errorf("watchPrefix: %s", s.watchPrefix()) })
		// watch BGP configuration
		s.t.Go(func() error { return fmt.Errorf("watchBGPConfig: %s", s.watchBGPConfig()) })
	} else if s.datastore == calicoapi.Kubernetes {
		s.t.Go(func() error { return fmt.Errorf("k8s interval loop: %s", s.process.IntervalLoop()) })
	}
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
	p := &ipPool{CIDR: subnet.String()}
	result := !p.contain(gw.String() + "/32")
	return result
}

func (s *Server) ipamUpdateHandler(pool *ipPool) error {
	filter := &netlink.Route{
		Protocol: RTPROT_GOBGP,
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	node, err := s.client.Nodes().Get(calicoapi.NodeMetadata{Name: os.Getenv(NODENAME)})
	if err != nil {
		return err
	}

	for _, route := range list {
		if route.Dst == nil {
			continue
		}
		prefix := route.Dst.String()
		if pool.contain(prefix) {
			ipip := pool.IPIP != ""
			if pool.Mode == "cross-subnet" && !isCrossSubnet(route.Gw, node.Spec.BGP.IPv4Address.Network().IPNet) {
				ipip = false
			}
			if ipip {
				i, err := net.InterfaceByName(pool.IPIP)
				if err != nil {
					return err
				}
				route.LinkIndex = i.Index
				route.SetFlag(netlink.FLAG_ONLINK)
			} else {
				tbl, err := s.bgpServer.GetRib("", bgp.RF_IPv4_UC, []*bgptable.LookupPrefix{
					&bgptable.LookupPrefix{
						Prefix: prefix,
					},
				})
				if err != nil {
					return err
				}
				bests := tbl.Bests("")
				if len(bests) == 0 {
					log.Printf("no best for %s", prefix)
					continue
				}
				best := bests[0]
				if best.IsLocal() {
					log.Printf("%s's best is local path", prefix)
					continue
				}
				gw, err := recursiveNexthopLookup(best.GetNexthop())
				if err != nil {
					return err
				}
				route.Gw = gw
				route.Flags = 0
				rs, err := netlink.RouteGet(gw)
				if err != nil {
					return err
				}
				if len(rs) == 0 {
					return fmt.Errorf("no route for path: %s", gw)
				}
				r := rs[0]
				route.LinkIndex = r.LinkIndex
			}
			return netlink.RouteReplace(&route)
		}
	}
	return nil
}

func (s *Server) getNodeASN() (numorstring.ASNumber, error) {
	return s.getPeerASN(os.Getenv(NODENAME))
}

func (s *Server) getPeerASN(host string) (numorstring.ASNumber, error) {
	node, err := s.client.Nodes().Get(calicoapi.NodeMetadata{Name: host})
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

func (s *Server) getGlobalConfig() (*bgpconfig.Global, error) {
	asn, err := s.getNodeASN()
	if err != nil {
		return nil, err
	}
	return &bgpconfig.Global{
		Config: bgpconfig.GlobalConfig{
			As:       uint32(asn),
			RouterId: s.ipv4.String(),
		},
	}, nil
}

func (s *Server) isMeshMode() (bool, error) {
	return s.client.Config().GetNodeToNodeMesh()
}

// getMeshNeighborConfigs returns the list of mesh BGP neighbor configuration struct
func (s *Server) getMeshNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	globalASN, err := s.getNodeASN()
	if err != nil {
		return nil, err
	}
	nodes, err := s.client.Nodes().List(calicoapi.NodeMetadata{})
	if err != nil {
		return nil, err
	}
	ns := make([]*bgpconfig.Neighbor, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		if node.Metadata.Name == os.Getenv(NODENAME) {
			continue
		}
		peerASN := globalASN
		spec := node.Spec.BGP
		if spec == nil {
			continue
		}

		asn := spec.ASNumber
		if asn != nil {
			peerASN = *asn
		}
		if v4 := spec.IPv4Address; v4 != nil {
			ip := v4.IP.String()
			id := strings.Replace(ip, ".", "_", -1)
			ns = append(ns, &bgpconfig.Neighbor{
				Config: bgpconfig.NeighborConfig{
					NeighborAddress: ip,
					PeerAs:          uint32(peerASN),
					Description:     fmt.Sprintf("Mesh_%s", id),
				},
			})
		}
		if v6 := spec.IPv6Address; v6 != nil {
			ip := v6.IP.String()
			id := strings.Replace(ip, ":", "_", -1)
			ns = append(ns, &bgpconfig.Neighbor{
				Config: bgpconfig.NeighborConfig{
					NeighborAddress: ip,
					PeerAs:          uint32(peerASN),
					Description:     fmt.Sprintf("Mesh_%s", id),
				},
			})
		}
	}
	return ns, nil

}

// getNeighborConfigFromPeer returns a BGP neighbor configuration struct from *etcd.Node
func getNeighborConfigFromPeer(peer string, neighborType string) (*bgpconfig.Neighbor, error) {
	m := &struct {
		IP  string `json:"ip"`
		ASN string `json:"as_num"`
	}{}
	if err := json.Unmarshal([]byte(peer), m); err != nil {
		return nil, err
	}
	asn, err := numorstring.ASNumberFromString(m.ASN)
	if err != nil {
		return nil, err
	}
	return &bgpconfig.Neighbor{
		Config: bgpconfig.NeighborConfig{
			NeighborAddress: m.IP,
			PeerAs:          uint32(asn),
			Description:     fmt.Sprintf("%s_%s", strings.Title(neighborType), underscore(m.IP)),
		},
	}, nil
}

// getNonMeshNeighborConfigs returns the list of non-mesh BGP neighbor configuration struct
// valid neighborType is either "global" or "node"
func (s *Server) getNonMeshNeighborConfigs(neighborType string) ([]*bgpconfig.Neighbor, error) {
	var metadata calicoapi.BGPPeerMetadata
	switch neighborType {
	case "global":
		metadata.Scope = calicoscope.Global
	case "node":
		metadata.Scope = calicoscope.Node
		metadata.Node = os.Getenv(NODENAME)
	default:
		return nil, fmt.Errorf("invalid neighbor type: %s", neighborType)
	}
	list, err := s.client.BGPPeers().List(metadata)
	if err != nil {
		return nil, err
	}
	ns := make([]*bgpconfig.Neighbor, 0, len(list.Items))
	for _, node := range list.Items {
		addr := node.Metadata.PeerIP.String()
		ns = append(ns, &bgpconfig.Neighbor{
			Config: bgpconfig.NeighborConfig{
				NeighborAddress: addr,
				PeerAs:          uint32(node.Spec.ASNumber),
				Description:     fmt.Sprintf("%s_%s", strings.Title(neighborType), underscore(addr)),
			},
		})
	}
	return ns, nil
}

// getGlobalNeighborConfigs returns the list of global BGP neighbor configuration struct
func (s *Server) getGlobalNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	return s.getNonMeshNeighborConfigs("global")
}

// getNodeNeighborConfigs returns the list of node specific BGP neighbor configuration struct
func (s *Server) getNodeSpecificNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	return s.getNonMeshNeighborConfigs("node")
}

// getNeighborConfigs returns the complete list of BGP neighbor configuration
// which the node should peer.
func (s *Server) getNeighborConfigs() ([]*bgpconfig.Neighbor, error) {
	var neighbors []*bgpconfig.Neighbor
	// --- Node-to-node mesh ---
	if mesh, err := s.isMeshMode(); err == nil && mesh {
		ns, err := s.getMeshNeighborConfigs()
		if err != nil {
			return nil, err
		}
		neighbors = append(neighbors, ns...)
	} else if err != nil {
		return nil, err
	}
	// --- Global peers ---
	if ns, err := s.getGlobalNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	// --- Node-specific peers ---
	if ns, err := s.getNodeSpecificNeighborConfigs(); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	return neighbors, nil
}

func etcdKeyToPrefix(key string) string {
	path := strings.Split(key, "/")
	return strings.Replace(path[len(path)-1], "-", "/", 1)
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

	var nlri bgp.AddrPrefixInterface
	var family bgpapi.Family
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	if v4 {
		nlri = bgp.NewIPAddrPrefix(uint8(masklen), p.String())
		family = Family_AFI_IP
		attrs = append(attrs, bgp.NewPathAttributeNextHop(s.ipv4.String()))
	} else {
		nlri = bgp.NewIPv6AddrPrefix(uint8(masklen), p.String())
		family = Family_AFI_IP6
		attrs = append(attrs, bgp.NewPathAttributeMpReachNLRI(s.ipv6.String(), []bgp.AddrPrefixInterface{nlri}))
	}

	return &bgpapi.Path{
		Nlri: nlri,
		IsWithdraw: isWithdrawal,
		Pattrs: attrs,
		Age: time.Now(),
		Family: family,
	}, nil
}

// getAssignedPrefixes retrives prefixes assigned to the node and returns them as a
// list of BGP path.
// using etcd directly since libcalico-go doesn't seem to have a method to return
// assigned prefixes yet.
func (s *Server) getAssignedPrefixes(api etcd.KeysAPI) ([]*bgptable.Path, uint64, error) {
	var ps []*bgptable.Path
	var index uint64
	f := func(version string) error {
		res, err := api.Get(
			context.Background(),
			fmt.Sprintf("%s/%s/%s/block", CALICO_AGGR, os.Getenv(NODENAME), version),
			&etcd.GetOptions{Recursive: true}
		)
		if err != nil {
			return err
		}
		if index == 0 {
			index = res.Index
		}
		for _, v := range res.Node.Nodes {
			path, err := s.makePath(etcdKeyToPrefix(v.Key), false)
			if err != nil {
				return err
			}
			ps = append(ps, path)
		}
		return nil
	}
	if s.ipv4 != nil {
		if err := f("ipv4"); err != nil {
			return nil, 0, err
		}
	}
	if s.ipv6 != nil {
		if err := f("ipv6"); err != nil {
			return nil, 0, err
		}
	}
	return ps, index, nil
}

// watchPrefix watches etcd /calico/ipam/v2/host/$NODENAME and add/delete
// aggregated routes which are assigned to the node.
// This function also updates policy appropriately.
func (s *Server) watchPrefix() error {

	paths, index, err := s.getAssignedPrefixes(s.etcd)
	if err != nil {
		return err
	}

	if err = s.updatePrefixSet(paths); err != nil {
		return err
	}

	if _, err := s.bgpServer.AddPath("", paths); err != nil {
		return err
	}
	s.prefixReady <- 1

	watcher := s.etcd.Watcher(
		fmt.Sprintf("%s/%s", CALICO_AGGR, os.Getenv(NODENAME)),
		&etcd.WatcherOptions{Recursive: true, AfterIndex: index}
	)
	for {
		var err error
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		var path *bgptable.Path
		key := etcdKeyToPrefix(res.Node.Key)
		if res.Action == "delete" {
			path, err = s.makePath(key, true)
		} else {
			path, err = s.makePath(key, false)
		}
		if err != nil {
			return err
		}
		paths := []*bgptable.Path{path}
		if err = s.updatePrefixSet(paths); err != nil {
			return err
		}
		if _, err := s.bgpServer.AddPath("", paths); err != nil {
			return err
		}
		log.Printf("add path: %s", path)
	}
}

func (s *Server) AddNeighbor(n *bgpconfig.Neighbor) error {
	n.GracefulRestart.Config.Enabled = true
	n.GracefulRestart.Config.RestartTime = 120
	n.GracefulRestart.Config.LongLivedEnabled = true
	n.GracefulRestart.Config.NotificationEnabled = true
	ipAddr, err := net.ResolveIPAddr("ip", n.Config.NeighborAddress)
	var typ bgpconfig.AfiSafiType
	if err == nil {
		if ipAddr.IP.To4() == nil {
			typ = bgpconfig.AFI_SAFI_TYPE_IPV6_UNICAST
		} else {
			typ = bgpconfig.AFI_SAFI_TYPE_IPV4_UNICAST
		}
	}

	n.AfiSafis = []bgpconfig.AfiSafi{
		bgpconfig.AfiSafi{
			Config: bgpconfig.AfiSafiConfig{
				AfiSafiName: typ,
				Enabled:     true,
			},
			MpGracefulRestart: bgpconfig.MpGracefulRestart{
				Config: bgpconfig.MpGracefulRestartConfig{
					Enabled: true,
				},
			},
			State: bgpconfig.AfiSafiState{
				AfiSafiName: typ,
			},
		},
	}
	log.Printf("AddNeighbor neighbor=%#v", n)
	log.Printf("AddNeighbor neighbor=%s", n)
	if err := s.bgpServer.AddNeighbor(n); err != nil {
		return err
	}
	return nil
}

// watchBGPConfig watches etcd path /calico/bgp/v1 and handle various changes
// in etcd. Though this method tries to minimize effects to the existing BGP peers,
// when /calico/bgp/v1/host/$NODENAME or /calico/global/as_num is changed,
// give up handling the change and return error (this leads calico-bgp-daemon to be restarted)
func (s *Server) watchBGPConfig() error {
	var index uint64
	res, err := s.etcd.Get(context.Background(), CALICO_BGP, nil)
	if err != nil {
		return err
	}
	index = res.Index

	neighborConfigs, err := s.getNeighborConfigs()
	if err != nil {
		return err
	}

	for _, n := range neighborConfigs {
		if err = s.AddNeighbor(n); err != nil {
			return err
		}
	}

	watcher := s.etcd.Watcher(CALICO_BGP, &etcd.WatcherOptions{Recursive: true, AfterIndex: index})
	for {
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		prev := ""
		if res.PrevNode != nil {
			prev = res.PrevNode.Value
		}
		log.Printf("watch: action: %s, key: %s node: %s, prev-node: %s", res.Action, res.Node.Key, res.Node.Value, prev)
		if res.Action == "set" && res.Node.Value == prev {
			log.Printf("same value. ignore")
			continue
		}

		handleNonMeshNeighbor := func(neighborType string) error {
			switch res.Action {
			case "delete":
				n, err := getNeighborConfigFromPeer(res.PrevNode.Value, neighborType)
				if err != nil {
					return err
				}
				return s.bgpServer.DeleteNeighbor(n)
			case "set", "create", "update", "compareAndSwap":
				n, err := getNeighborConfigFromPeer(res.Node.Value, neighborType)
				if err != nil {
					return err
				}
				return s.AddNeighbor(n)
			}
			log.Printf("unhandled action: %s", res.Action)
			return nil
		}

		key := res.Node.Key
		switch {
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/peer_", CALICO_BGP)):
			err = handleNonMeshNeighbor("global")
		case strings.HasPrefix(key, fmt.Sprintf("%s/host/%s/peer_", CALICO_BGP, os.Getenv(NODENAME))):
			err = handleNonMeshNeighbor("node")
		case strings.HasPrefix(key, fmt.Sprintf("%s/host/%s", CALICO_BGP, os.Getenv(NODENAME))):
			log.Println("Local host config update. Restart")
			os.Exit(1)
		case strings.HasPrefix(key, fmt.Sprintf("%s/host", CALICO_BGP)):
			elems := strings.Split(key, "/")
			if len(elems) < 4 {
				log.Printf("unhandled key: %s", key)
				continue
			}
			deleteNeighbor := func(node *etcd.Node) error {
				if node.Value == "" {
					return nil
				}
				n := &bgpconfig.Neighbor{
					Config: bgpconfig.NeighborConfig{
						NeighborAddress: node.Value,
					},
				}
				return s.bgpServer.DeleteNeighbor(n)
			}
			host := elems[len(elems)-2]
			switch elems[len(elems)-1] {
			case "ip_addr_v4", "ip_addr_v6":
				switch res.Action {
				case "delete":
					if err = deleteNeighbor(res.PrevNode); err != nil {
						return err
					}
				case "set":
					if res.PrevNode != nil {
						if err = deleteNeighbor(res.PrevNode); err != nil {
							return err
						}
					}
					if res.Node.Value == "" {
						continue
					}
					asn, err := s.getPeerASN(host)
					if err != nil {
						return err
					}
					n := &bgpconfig.Neighbor{
						Config: bgpconfig.NeighborConfig{
							NeighborAddress: res.Node.Value,
							PeerAs:          uint32(asn),
							Description:     fmt.Sprintf("Mesh_%s", underscore(res.Node.Value)),
						},
					}
					if err = s.AddNeighbor(n); err != nil {
						return err
					}
				}
			case "as_num":
				var asn numorstring.ASNumber
				if res.Action == "set" {
					asn, err = numorstring.ASNumberFromString(res.Node.Value)
					if err != nil {
						return err
					}
				} else {
					asn, err = s.getNodeASN()
					if err != nil {
						return err
					}
				}
				for _, version := range []string{"v4", "v6"} {
					res, err := s.etcd.Get(
						context.Background(),
						fmt.Sprintf("%s/host/%s/ip_addr_%s", CALICO_BGP, host, version),
						nil
					)
					if errorButKeyNotFound(err) != nil {
						return err
					}
					if res == nil {
						continue
					}
					if err = deleteNeighbor(res.Node); err != nil {
						return err
					}
					ip := res.Node.Value
					n := &bgpconfig.Neighbor{
						Config: bgpconfig.NeighborConfig{
							NeighborAddress: ip,
							PeerAs:          uint32(asn),
							Description:     fmt.Sprintf("Mesh_%s", underscore(ip)),
						},
					}
					if err = s.AddNeighbor(n); err != nil {
						return err
					}
				}
			default:
				log.Printf("unhandled key: %s", key)
			}
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/as_num", CALICO_BGP)):
			log.Println("Global AS number update. Restart")
			os.Exit(1)
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/node_mesh", CALICO_BGP)):
			mesh, err := s.isMeshMode()
			if err != nil {
				return err
			}
			ns, err := s.getMeshNeighborConfigs()
			if err != nil {
				return err
			}
			for _, n := range ns {
				if mesh {
					err = s.AddNeighbor(n)
				} else {
					err = s.bgpServer.DeleteNeighbor(n)
				}
				if err != nil {
					return err
				}
			}
		}
		if err != nil {
			return err
		}
	}
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
			if _, err = s.bgpServer.AddPath("", []*bgptable.Path{path}); err != nil {
				return err
			}
		} else if update.Table == syscall.RT_TABLE_LOCAL {
			// This means the interface address is updated
			// Some routes we injected may be deleted by the kernel
			// Reload routes from BGP RIB and inject again
			ip, _, _ := net.ParseCIDR(update.Dst.String())
			family := bgp.RF_IPv4_UC
			if ip.To4() == nil {
				family = bgp.RF_IPv6_UC
			}
			tbl, err := s.bgpServer.GetRib("", family, nil)
			if err != nil {
				return err
			}
			s.reloadCh <- tbl.Bests("")
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
			if _, err = s.bgpServer.AddPath("", []*bgptable.Path{path}); err != nil {
				return err
			}
		}
	}
	return nil
}

// injectRoute is a helper function to inject BGP routes to VPP
// TODO: multipath support
// TODO: ipip support
func (s *Server) injectRoute(path *bgptable.Path) error {
	nexthop := path.GetNexthop()
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
			ipip = p.IPIP != ""

			node, err := s.client.Nodes().Get(calicoapi.NodeMetadata{Name: os.Getenv(NODENAME)})
			if err != nil {
				return err
			}

			if p.Mode == "cross-subnet" && !isCrossSubnet(route.Gw, node.Spec.BGP.IPv4Address.Network().IPNet) {
				ipip = false
			}
			if ipip {
				// TODO
				panic("Not implemented - disable IPIP")
				// i, err := net.InterfaceByName(p.IPIP)
				// if err != nil {
				// 	return err
				// }
				// route.LinkIndex = i.Index
				// route.SetFlag(netlink.FLAG_ONLINK)
			}
		}
		// TODO: if !IsWithdraw, we'd ignore that
	}

	if path.IsWithdraw {
		log.Printf("removed route %s from VPP", nlri)
		return netlink.RouteDel(route)
	}
	if !ipip {
		// gw, err := recursiveNexthopLookup(path.GetNexthop())
		// if err != nil {
		// 	return err
		// }
		// route.Gw = gw
	}
	log.Printf("added route %s to kernel %s", nlri, route)
	return netlink.RouteReplace(route)
}

// watchBGPPath watches BGP routes from other peers and inject them into
// linux kernel
// TODO: multipath support
func (s *Server) watchBGPPath() error {
	watcher := s.bgpServer.Watch(bgpserver.WatchBestPath(false))
	for {
		var paths []*bgptable.Path
		select {
		case ev := <-watcher.Event():
			msg, ok := ev.(*bgpserver.WatchEventBestPath)
			if !ok {
				continue
			}
			paths = msg.PathList
		case paths = <-s.reloadCh:
		}
		for _, path := range paths {
			if path.IsLocal() {
				continue
			}
			if err := s.injectRoute(path); err != nil {
				return err
			}
		}
	}
}

// initialPolicySetting initialize BGP export policy.
// this creates two prefix-sets named 'aggregated' and 'host'.
// A route is allowed to be exported when it matches with 'aggregated' set,
// and not allowed when it matches with 'host' set.
func (s *Server) initialPolicySetting() error {
	createEmptyPrefixSet := func(name string) error {
		ps, err := bgptable.NewPrefixSet(bgpconfig.PrefixSet{PrefixSetName: name})
		if err != nil {
			return err
		}
		return s.bgpServer.AddDefinedSet(ps)
	}
	for _, name := range []string{aggregatedPrefixSetName, hostPrefixSetName} {
		if err := createEmptyPrefixSet(name); err != nil {
			return err
		}
	}
	// intended to work as same as 'calico_pools' export filter of BIRD configuration
	definition := bgpconfig.PolicyDefinition{
		Name: "calico_aggr",
		Statements: []bgpconfig.Statement{
			bgpconfig.Statement{
				Conditions: bgpconfig.Conditions{
					MatchPrefixSet: bgpconfig.MatchPrefixSet{
						PrefixSet: aggregatedPrefixSetName,
					},
				},
				Actions: bgpconfig.Actions{
					RouteDisposition: bgpconfig.ROUTE_DISPOSITION_ACCEPT_ROUTE,
				},
			},
			bgpconfig.Statement{
				Conditions: bgpconfig.Conditions{
					MatchPrefixSet: bgpconfig.MatchPrefixSet{
						PrefixSet: hostPrefixSetName,
					},
				},
				Actions: bgpconfig.Actions{
					RouteDisposition: bgpconfig.ROUTE_DISPOSITION_REJECT_ROUTE,
				},
			},
		},
	}
	policy, err := bgptable.NewPolicy(definition)
	if err != nil {
		return err
	}
	if err = s.bgpServer.AddPolicy(policy, false); err != nil {
		return err
	}
	return s.bgpServer.AddPolicyAssignment("", bgptable.POLICY_DIRECTION_EXPORT,
		[]*bgpconfig.PolicyDefinition{&definition},
		bgptable.ROUTE_TYPE_ACCEPT)
}

func (s *Server) updatePrefixSet(paths []*bgptable.Path) error {
	for _, path := range paths {
		err := s._updatePrefixSet(path.GetNlri().String(), path.IsWithdraw)
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
func (s *Server) _updatePrefixSet(prefix string, del bool) error {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}
	ps, err := bgptable.NewPrefixSet(bgpconfig.PrefixSet{
		PrefixSetName: aggregatedPrefixSetName,
		PrefixList: []bgpconfig.Prefix{
			bgpconfig.Prefix{
				IpPrefix: prefix,
			},
		},
	})
	if err != nil {
		return err
	}
	if del {
		err = s.bgpServer.DeleteDefinedSet(ps, false)
	} else {
		err = s.bgpServer.AddDefinedSet(ps)
	}
	if err != nil {
		return err
	}
	min, _ := ipNet.Mask.Size()
	max := 32
	if ipNet.IP.To4() == nil {
		max = 128
	}
	ps, err = bgptable.NewPrefixSet(bgpconfig.PrefixSet{
		PrefixSetName: hostPrefixSetName,
		PrefixList: []bgpconfig.Prefix{
			bgpconfig.Prefix{
				IpPrefix:        prefix,
				MasklengthRange: fmt.Sprintf("%d..%d", min, max),
			},
		},
	})
	if err != nil {
		return err
	}
	if del {
		return s.bgpServer.DeleteDefinedSet(ps, false)
	}
	return s.bgpServer.AddDefinedSet(ps)
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
