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
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	bgpapi "github.com/osrg/gobgp/api"
	bgpserver "github.com/osrg/gobgp/pkg/server"
	"github.com/pkg/errors"
	calicov3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	calicocliv3 "github.com/projectcalico/libcalico-go/lib/clientv3"
	calicoerr "github.com/projectcalico/libcalico-go/lib/errors"
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

	prefixWatchInterval = 60 * time.Second
)

var (
	bgpFamilyUnicastIPv4 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP, Safi: bgpapi.Family_SAFI_UNICAST}
	bgpFamilyUnicastIPv6 = bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_UNICAST}
)

type IpamCache interface {
	match(net.IPNet) *calicov3.IPPool
	update(*calicov3.IPPool, bool) error
	sync() error
}

// VERSION is filled out during the build process (using git describe output)
var VERSION string

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
	vpp            *vppInterface
}

func NewServer() (*Server, error) {
	nodeName := os.Getenv(NODENAME)
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

	vpp, err := newVppInterface("", log.WithFields(log.Fields{"subcomponent": "vpp-api"}))
	if err != nil {
		return nil, errors.Wrap(err, "error creating VPP client interface")
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
		vpp:         vpp,
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
		log.Fatal("cannot get global configuration: ", err)
	}

	if err := s.bgpServer.StartBgp(context.Background(), &bgpapi.StartBgpRequest{
		Global: globalConfig,
	}); err != nil {
		log.Fatal("failed to start BGP server:", err)
	}

	if err := s.initialPolicySetting(); err != nil {
		log.Fatal("error configuring initial policies: ", err)
	}

	s.ipam = newIPAMCache(s.clientv3, s.ipamUpdateHandler)
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

	<-s.t.Dying()

	if err := cleanUpRoutes(); err != nil {
		log.Fatalf("%s, also failed to clean up routes which we injected: %s", s.t.Err(), err)
	}
	log.Fatal(s.t.Err())

}

func isCrossSubnet(gw net.IP, subnet net.IPNet) bool {
	return !subnet.Contains(gw)
}

func (s *Server) ipamUpdateHandler(pool *calicov3.IPPool) error {
	log.Debugf("Pool %s updated, handler called", pool.Spec.CIDR)
	// TODO check if we need to change any routes based on VXLAN / IPIPMode config changes
	return fmt.Errorf("IPPool updates not supported at this time")
}

// TODO: cache this? and watch for changes - reboot in case of changes
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
		log.Debug("No \"default\" BGP config found, using default options")
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

// getAssignedPrefixes retrives prefixes assigned to the node and returns them as a
// list of BGP path.
// using backend directly since libcalico-go doesn't seem to have a method to return
// assigned prefixes yet.
func (s *Server) getAssignedPrefixes() ([]string, error) {
	var ps []string

	f := func(ipVersion int) error {
		blockList, err := s.client.Backend.List(
			context.Background(),
			model.BlockAffinityListOptions{Host: os.Getenv(NODENAME), IPVersion: ipVersion},
			"",
		)
		if err != nil {
			return err
		}
		for _, block := range blockList.KVPairs {
			log.Debugf("Found assigned prefix: %+v", block)
			key := block.Key.(model.BlockAffinityKey)
			value := block.Value.(*model.BlockAffinity)
			if value.State == model.StateConfirmed && !value.Deleted {
				ps = append(ps, key.CIDR.String())
			}
		}
		return nil
	}

	if s.ipv4 != nil {
		if err := f(4); err != nil {
			return nil, err
		}
	}
	if s.ipv6 != nil {
		if err := f(6); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

// watchPrefix watches etcd /calico/ipam/v2/host/$NODENAME and add/delete
// aggregated routes which are assigned to the node.
// This function also updates policy appropriately.
func (s *Server) watchPrefix() error {
	assignedPrefixes := make(map[string]bool)
	// There is no need to react instantly to these changes, and the calico API
	// doesn't provide a way to watch for changes, so we just poll every minute
	for {
		log.Infof("Reconciliating prefix affinities...")
		newPrefixes, err := s.getAssignedPrefixes()
		if err != nil {
			return errors.Wrap(err, "error getting assigned prefixes")
		}
		log.Debugf("Found %d assigned prefixes", len(newPrefixes))
		newAssignedPrefixes := make(map[string]bool)
		var toAdd []*bgpapi.Path
		for _, prefix := range newPrefixes {
			if _, found := assignedPrefixes[prefix]; found {
				log.Debugf("Prefix %s is still assigned to us", prefix)
				assignedPrefixes[prefix] = true     // Prefix is still there, set value to true so we don't delete it
				newAssignedPrefixes[prefix] = false // Record it in new map
			} else {
				log.Debugf("New assigned prefix: %s", prefix)
				newAssignedPrefixes[prefix] = false
				path, err := s.makePath(prefix, false)
				if err != nil {
					return errors.Wrap(err, "error making new path for assigned prefix")
				}
				toAdd = append(toAdd, path)
			}
		}
		if err = s.updatePrefixSet(toAdd); err != nil {
			return errors.Wrap(err, "error adding prefix announcements")
		}
		// Remove paths that don't exist anymore
		var toRemove []*bgpapi.Path
		for p, stillThere := range assignedPrefixes {
			if !stillThere {
				log.Infof("Prefix %s is not assigned to us anymore", p)
				path, err := s.makePath(p, true)
				if err != nil {
					return errors.Wrap(err, "error making new path for removed prefix")
				}
				toRemove = append(toRemove, path)
			}
		}
		if err = s.updatePrefixSet(toRemove); err != nil {
			return errors.Wrap(err, "error removing prefix announcements")
		}
		assignedPrefixes = newAssignedPrefixes

		time.Sleep(prefixWatchInterval)
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
	log.Infof("Adding BGP neighbor: %+v", peer)
	err = s.bgpServer.AddPeer(context.Background(), &bgpapi.AddPeerRequest{Peer: peer})
	return err
}

func (s *Server) updateBGPPeer(ip string, asn uint32) error {
	peer, err := s.createBGPPeer(ip, asn)
	if err != nil {
		return err
	}
	log.Infof("Updating BGP neighbor: %+v", peer)
	_, err = s.bgpServer.UpdatePeer(context.Background(), &bgpapi.UpdatePeerRequest{Peer: peer})
	return err
}

func (s *Server) deleteBGPPeer(ip string) error {
	log.Infof("Adding BGP neighbor: %s", ip)
	err := s.bgpServer.DeletePeer(context.Background(), &bgpapi.DeletePeerRequest{Address: ip})
	return err
}

type bgpPeer struct {
	AS        uint32
	SweepFlag bool
}

func (s *Server) shouldPeer(peer *calicov3.BGPPeer) bool {
	if peer.Spec.Node != "" && peer.Spec.Node != s.nodeName {
		return false
	}
	return true
}

func (s *Server) watchBGPPeers() error {
	state := make(map[string]*bgpPeer)

	for {
		log.Debugf("Reconciliating peers...")
		peers, err := s.clientv3.BGPPeers().List(context.Background(), options.ListOptions{})
		if err != nil {
			return err
		}
		for _, p := range state {
			p.SweepFlag = true
		}
		for _, peer := range peers.Items {
			if !s.shouldPeer(&peer) {
				continue
			}
			ip := peer.Spec.PeerIP
			asn := uint32(peer.Spec.ASNumber)
			existing, ok := state[ip]
			if ok {
				existing.SweepFlag = false
				if existing.AS != asn {
					existing.AS = asn
					err := s.updateBGPPeer(ip, asn)
					if err != nil {
						return errors.Wrap(err, "error updating BGP peer")
					}
				}
				// Else no change, nothing to do
			} else {
				// New peer
				state[ip] = &bgpPeer{
					AS:        asn,
					SweepFlag: false,
				}
				err := s.addBGPPeer(ip, asn)
				if err != nil {
					return errors.Wrap(err, "error adding BGP peer")
				}
			}
		}
		// Remove all peers that still have sweepflag to true
		for ip, peer := range state {
			if peer.SweepFlag {
				err := s.deleteBGPPeer(ip)
				if err != nil {
					return errors.Wrap(err, "error deleting BGP peer")
				}
				delete(state, ip)
			}
		}

		revision := peers.ResourceVersion
		watcher, err := s.clientv3.BGPPeers().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: revision},
		)
		if err != nil {
			return err
		}
	watch:
		for update := range watcher.ResultChan() {
			switch update.Type {
			case watch.Added, watch.Modified:
				peer := update.Object.(*calicov3.BGPPeer)
				if !s.shouldPeer(peer) {
					continue
				}
				ip := peer.Spec.PeerIP
				asn := uint32(peer.Spec.ASNumber)
				existing, ok := state[ip]
				if ok {
					if existing.AS != asn {
						existing.AS = asn
						err := s.updateBGPPeer(ip, asn)
						if err != nil {
							return errors.Wrap(err, "error updating BGP peer")
						}
					}
					// Else no change, nothing to do
				} else {
					// New peer
					state[ip] = &bgpPeer{
						AS:        asn,
						SweepFlag: false,
					}
					err := s.addBGPPeer(ip, asn)
					if err != nil {
						return errors.Wrap(err, "error adding BGP peer")
					}
				}
			case watch.Deleted:
				peer := update.Previous.(*calicov3.BGPPeer)
				if !s.shouldPeer(peer) {
					continue
				}
				ip := peer.Spec.PeerIP
				_, ok := state[ip]
				if !ok {
					log.Warnf("Deleted peer %s not found", ip)
					continue
				}
				err := s.deleteBGPPeer(ip)
				if err != nil {
					return errors.Wrap(err, "error deleting BGP peer")
				}
				delete(state, ip)
			case watch.Error:
				switch update.Error.(type) {
				case calicoerr.ErrorWatchTerminated:
					break watch
				default:
					return errors.Wrap(err, "BGP Peers watch errored")
				}
			}
		}
	}
	return nil
}

// Returns true if the config of the current node has changed and requires a restart
// Sets node.SweepFlag to false if an existing node is added to allow mark and sweep
func (s *Server) handleNodeUpdate(
	state map[string]*node,
	nodeName string,
	newSpec *calicov3.NodeSpec,
	eventType watch.EventType,
	isMesh bool,
) (bool, error) {
	log.Tracef("Got node update: mesh:%t %s %s %+v %v", isMesh, eventType, nodeName, newSpec, state)
	if nodeName == s.nodeName {
		// No need to manage ourselves, but if we change we need to restart and reconfigure
		if eventType == watch.Deleted {
			return true, nil
		} else {
			old, found := state[nodeName]
			if found {
				// Check that there were no changes, restart if our BGP config changed
				old.SweepFlag = false
				log.Tracef("node comparison: old:%+v new:%+v", old.Spec.BGP, newSpec.BGP)
				return !reflect.DeepEqual(old.Spec.BGP, newSpec.BGP), nil
			} else {
				// First pass, create local node
				state[nodeName] = &node{
					Spec:      newSpec,
					SweepFlag: false,
				}
				return false, nil
			}
		}
	}

	// If the mesh is disabled, discard all updates that aren't on the current node
	if !isMesh || newSpec.BGP == nil { // No BGP config for this node
		return false, nil
	}
	// This ensures that nodes that don't have a BGP Spec are never present in the state map

	var v4IP, v6IP net.IP
	var asNumber uint32
	var err error
	if newSpec.BGP.ASNumber == nil {
		asNumber = uint32(*s.defaultBGPConf.ASNumber)
	} else {
		asNumber = uint32(*newSpec.BGP.ASNumber)
	}
	v4Set := newSpec.BGP.IPv4Address != ""
	if v4Set {
		v4IP, _, err = net.ParseCIDR(newSpec.BGP.IPv4Address)
		if err != nil {
			return false, errors.Wrapf(err, "cannot parse node v4: %s", newSpec.BGP.IPv4Address)
		}
	}
	v6Set := newSpec.BGP.IPv6Address != ""
	if v6Set {
		v6IP, _, err = net.ParseCIDR(newSpec.BGP.IPv6Address)
		if err != nil {
			return false, errors.Wrapf(err, "cannot parse node v6: %s", newSpec.BGP.IPv6Address)
		}
	}
	switch eventType {
	case watch.Error: // Shouldn't happen
	case watch.Added, watch.Modified:
		old, found := state[nodeName]
		if found {
			log.Tracef("node comparison: old:%+v new:%+v", old.Spec.BGP, newSpec.BGP)
			var oldASN uint32
			if old.Spec.BGP.ASNumber != nil {
				oldASN = uint32(*old.Spec.BGP.ASNumber)
			} else {
				oldASN = uint32(*s.defaultBGPConf.ASNumber)
			}
			oldV4Set := old.Spec.BGP.IPv4Address != ""
			oldV6Set := old.Spec.BGP.IPv6Address != ""
			var oldV4IP, oldV6IP net.IP
			if oldV4Set { // These shouldn't error since they have already been parsed successfully
				oldV4IP, _, _ = net.ParseCIDR(old.Spec.BGP.IPv4Address)
			}
			if oldV6Set {
				oldV6IP, _, _ = net.ParseCIDR(old.Spec.BGP.IPv6Address)
			}

			// Compare IPs and ASN
			if v4Set {
				if oldV4Set {
					if old.Spec.BGP.IPv4Address != newSpec.BGP.IPv4Address {
						// IP change, delete and re-add neighbor
						err = s.deleteBGPPeer(oldV4IP.String())
						if err != nil {
							return false, errors.Wrapf(err, "error deleting peer %s", oldV4IP.String())
						}
						err = s.addBGPPeer(v4IP.String(), asNumber)
						if err != nil {
							return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
						}
					} else {
						// Check for ASN change
						if oldASN != asNumber {
							// Update peer
							err = s.updateBGPPeer(v4IP.String(), asNumber)
							if err != nil {
								return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
							}
						} // Otherwise nothing to do for v4
					}
				} else {
					err = s.addBGPPeer(v4IP.String(), asNumber)
					if err != nil {
						return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
					}
				}
			} else {
				// No v4 address on new node
				if oldV4Set {
					// Delete old neighbor
					err = s.deleteBGPPeer(oldV4IP.String())
					if err != nil {
						return false, errors.Wrapf(err, "error deleting peer %s", oldV4IP.String())
					}
				} // Else nothing to do for v6
			}
			if v6Set {
				if oldV6Set {
					if old.Spec.BGP.IPv6Address != newSpec.BGP.IPv6Address {
						// IP change, delete and re-add neighbor
						err = s.deleteBGPPeer(oldV6IP.String())
						if err != nil {
							return false, errors.Wrapf(err, "error deleting peer %s", oldV6IP.String())
						}
						err = s.addBGPPeer(v6IP.String(), asNumber)
						if err != nil {
							return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
						}
					} else {
						// Check for ASN change
						if oldASN != asNumber {
							// Update peer
							err = s.updateBGPPeer(v6IP.String(), asNumber)
							if err != nil {
								return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
							}
						} // Otherwise nothing to do for v6
					}
				} else {
					err = s.addBGPPeer(v6IP.String(), asNumber)
					if err != nil {
						return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
					}
				}
			} else {
				// No v6 address on new node
				if oldV6Set {
					// Delete old neighbor
					err = s.deleteBGPPeer(oldV6IP.String())
					if err != nil {
						return false, errors.Wrapf(err, "error deleting peer %s", oldV6IP.String())
					}
				} // Else nothing to do for v6
			}
			old.SweepFlag = false
			old.Spec = newSpec
		} else {
			// New node
			state[nodeName] = &node{
				Spec:      newSpec,
				SweepFlag: false,
			}
			if v4Set {
				err = s.addBGPPeer(v4IP.String(), asNumber)
				if err != nil {
					return false, errors.Wrapf(err, "error adding peer %s", v4IP.String())
				}
			}
			if v6Set {
				err = s.addBGPPeer(v6IP.String(), asNumber)
				if err != nil {
					return false, errors.Wrapf(err, "error adding peer %s", v6IP.String())
				}
			}
		}
	case watch.Deleted:
		_, found := state[nodeName]
		// This assumes that the old spec and the new spec are identical.
		if found {
			if v4Set {
				err = s.deleteBGPPeer(v4IP.String())
				if err != nil {
					return false, errors.Wrapf(err, "error deleting peer %s", v4IP.String())
				}
			}
			if v6Set {
				err = s.deleteBGPPeer(v6IP.String())
				if err != nil {
					return false, errors.Wrapf(err, "error deleting peer %s", v6IP.String())
				}
			}
			delete(state, nodeName)
		} else {
			return false, fmt.Errorf("Node to delete not found")
		}

	}
	return false, nil
}

type node struct {
	Spec      *calicov3.NodeSpec
	SweepFlag bool
}

func nodeSpecCopy(s *calicov3.NodeSpec) *calicov3.NodeSpec {
	r := &calicov3.NodeSpec{
		IPv4VXLANTunnelAddr: s.IPv4VXLANTunnelAddr,
		VXLANTunnelMACAddr:  s.VXLANTunnelMACAddr,
		OrchRefs:            append([]calicov3.OrchRef{}, s.OrchRefs...),
	}
	if s.BGP != nil {
		r.BGP = &calicov3.NodeBGPSpec{
			IPv4Address:             s.BGP.IPv4Address,
			IPv6Address:             s.BGP.IPv6Address,
			IPv4IPIPTunnelAddr:      s.BGP.IPv4IPIPTunnelAddr,
			RouteReflectorClusterID: s.BGP.RouteReflectorClusterID,
		}
		if s.BGP.ASNumber != nil {
			r.BGP.ASNumber = new(numorstring.ASNumber)
			*r.BGP.ASNumber = *s.BGP.ASNumber
		}
	}
	return r
}

func (s *Server) watchNodes() error {
	isMesh, err := s.isMeshMode()
	if err != nil {
		return errors.Wrap(err, "error determining whether node mesh is enabled")
	}
	state := make(map[string]*node)

	for {
		// TODO: Get and watch only ourselves if there is no mesh
		log.Info("Syncing nodes...")
		nodes, err := s.clientv3.Nodes().List(context.Background(), options.ListOptions{})
		if err != nil {
			return errors.Wrap(err, "error listing nodes")
		}
		for _, n := range state {
			n.SweepFlag = true
		}
		for _, node := range nodes.Items {
			spec := nodeSpecCopy(&node.Spec)
			shouldRestart, err := s.handleNodeUpdate(state, node.Name, spec, watch.Added, isMesh)
			if err != nil {
				return errors.Wrap(err, "error handling node update")
			}
			if shouldRestart {
				log.Warnf("Current node configuration changed, restarting")
				return nil
			}
		}
		for name, node := range state {
			if node.SweepFlag {
				shouldRestart, err := s.handleNodeUpdate(state, name, node.Spec, watch.Deleted, isMesh)
				if err != nil {
					return errors.Wrap(err, "error handling node update")
				}
				if shouldRestart {
					log.Warnf("Current node configuration changed, restarting")
					return nil
				}
			}
		}

		watcher, err := s.clientv3.Nodes().Watch(
			context.Background(),
			options.ListOptions{ResourceVersion: nodes.ResourceVersion},
		)
		if err != nil {
			return errors.Wrap(err, "cannot watch nodes")
		}
	watch:
		for update := range watcher.ResultChan() {
			var node *calicov3.Node
			switch update.Type {
			case watch.Error:
				switch update.Error.(type) {
				case calicoerr.ErrorWatchTerminated:
					break watch
				default:
					return errors.Wrap(update.Error, "error while watching for Node updates")
				}
			case watch.Modified, watch.Added:
				node = update.Object.(*calicov3.Node)
			case watch.Deleted:
				node = update.Previous.(*calicov3.Node)
			}

			spec := nodeSpecCopy(&node.Spec)
			shouldRestart, err := s.handleNodeUpdate(state, node.Name, spec, update.Type, isMesh)
			if err != nil {
				return errors.Wrap(err, "error handling node update")
			}
			if shouldRestart {
				log.Warnf("Current node configuration changed, restarting")
				return nil
			}
		}
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
		log.Debugf("kernel update: %s", update)
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
				log.Debugf("unhandled rtm type: %d", update.Type)
				continue
			}
			path, err := s.makePath(update.Dst.String(), isWithdrawal)
			if err != nil {
				return err
			}
			log.Debugf("made path from kernel update: %s", path)
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
			log.Printf("made path from kernel route: %s", path)
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
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	var dst net.IPNet
	isV4 := false
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

	ipip := false
	if isV4 {
		if p := s.ipam.match(dst); p != nil {
			ipip = p.Spec.IPIPMode != calicov3.IPIPModeNever

			node, err := s.clientv3.Nodes().Get(context.Background(), s.nodeName, options.GetOptions{}) // TODO cache, we only do this to get the address subnet
			if err != nil {
				return errors.Wrap(err, "error getting node config")
			}
			_, ipNet, err := net.ParseCIDR(node.Spec.BGP.IPv4Address)
			if err != nil {
				return errors.Wrapf(err, "error parsing node IPv4 network: %s", node.Spec.BGP.IPv4Address)
			}

			if p.Spec.IPIPMode == calicov3.IPIPModeCrossSubnet && !isCrossSubnet(nexthop, *ipNet) {
				ipip = false
			}
			if ipip {
				log.Fatalf("ipip not supported at this time")
			}
		}
		// TODO: if !IsWithdraw, we'd ignore that
	}

	if path.IsWithdraw {
		log.Debugf("removing route %s from kernel", dst.String())
		return errors.Wrap(s.vpp.delRoute(isV4, dst, nexthop), "error deleting route")
	}
	log.Printf("adding route %s to kernel", dst.String())
	return errors.Wrap(s.vpp.replaceRoute(isV4, dst, nexthop), "error replacing route")
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
					log.Warnf("nil path update, skipping")
					return
				}
				log.Infof("Got path update from %s as %u", path.SourceId, path.SourceAsn)
				if path.NeighborIp == "<nil>" { // Weird GoBGP API behaviour
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
	log.Infof("Updating local prefix set with %+v", path)
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
		log.Debugf("Address %s detected as v6", prefixAddr)
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
	defer server.vpp.close()

	server.Serve()
}
