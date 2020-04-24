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
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/calico-vpp/vpplink"
	"github.com/calico-vpp/vpplink/types"

	pb "github.com/calico-vpp/calico-vpp/cni/proto"
	"github.com/calico-vpp/calico-vpp/config"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func ifNameToSwIfIdx(name string) (uint32, error) {
	var ret uint32
	_, err := fmt.Sscanf(name, "vpp-tap-%u", &ret)
	return ret, err
}

func swIfIdxToIfName(idx uint32) string {
	return fmt.Sprintf("vpp-tap-%d", idx)
}

// writeProcSys takes the sysctl path and a string value to set i.e. "0" or "1" and sets the sysctl.
// This method was copied from cni-plugin/internal/pkg/utils/network_linux.go
func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// configureContainerSysctls configures necessary sysctls required inside the container netns.
// This method was adapted from cni-plugin/internal/pkg/utils/network_linux.go
func (s *Server) configureContainerSysctls(allowIPForwarding, hasIPv4, hasIPv6 bool) error {
	ipFwd := "0"
	if allowIPForwarding {
		ipFwd = "1"
	}
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasIPv4 {
		s.log.Info("Configuring IPv4 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", ipFwd); err != nil {
			return err
		}
	}
	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasIPv6 {
		s.log.Info("Configuring IPv6 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", ipFwd); err != nil {
			return err
		}
	}
	return nil
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func (s *Server) SetupVppRoutes(swIfIndex uint32, ipConfigs []*pb.IPConfig) error {
	s.log.Infof("Configuring VPP side routes")
	// Go through all the IPs and add routes for each IP in the result.
	for _, ipAddr := range ipConfigs {
		ip := net.IPNet{}
		isIPv4 := !ipAddr.GetIp().GetIp().GetIsIpv6()
		ip.IP = ipAddr.GetIp().GetIp().GetIp()
		if isIPv4 {
			ip.Mask = net.CIDRMask(32, 32)
		} else {
			ip.Mask = net.CIDRMask(128, 128)
		}
		err := s.vpp.RouteAdd(&types.Route{
			Dst:       &ip,
			Gw:        ip.IP,
			SwIfIndex: swIfIndex,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}

		hardwareAddr, err := net.ParseMAC(config.ContainerSideMacAddressString)
		if err != nil {
			return errors.Wrapf(err, "Unable to parse mac: %s", config.ContainerSideMacAddressString)
		}
		logrus.WithFields(logrus.Fields{"IP": ipAddr.GetIp()}).Debugf("CNI adding VPP route")
		err = s.vpp.AddNeighbor(&types.Neighbor{
			SwIfIndex:    swIfIndex,
			IP:           ip.IP,
			HardwareAddr: hardwareAddr,
			Flags:        types.IPNeighborStatic,
		})
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}
	}
	return nil
}

func getPodv4IPNet(swIfIndex uint32) *net.IPNet {
	return &net.IPNet{
		IP:   net.IPv4(byte(169), byte(254), byte(swIfIndex>>8), byte(swIfIndex)),
		Mask: net.CIDRMask(32, 32),
	}
}

func getPodv6IPNet(swIfIndex uint32) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(swIfIndex >> 24), byte(swIfIndex >> 16), byte(swIfIndex >> 8), byte(swIfIndex)},
		Mask: net.CIDRMask(128, 128),
	}
}

func (s *Server) tapErrorCleanup(contTapName string, netns string, err error, msg string, args ...interface{}) error {
	s.log.Errorf("Error creating or configuring tap: %s", err)
	delErr := s.DelVppInterface(&pb.DelRequest{
		InterfaceName: contTapName,
		Netns:         netns,
	})
	if delErr != nil {
		s.log.Errorf("Error deleting tap on error %+v", delErr)
	}
	return errors.Wrapf(err, msg, args...)
}

func getMaxCIDRLen(isv6 bool) int {
	if isv6 {
		return 128
	} else {
		return 32
	}
}

func getMaxCIDRMask(addr net.IP) net.IPMask {
	maxCIDRLen := getMaxCIDRLen(vpplink.IsIP6(addr))
	return net.CIDRMask(maxCIDRLen, maxCIDRLen)
}

func (s *Server) getNamespaceSideGw(isv6 bool, swIfIndex uint32) (gwIp net.IP, err error) {
	if isv6 {
		// Retry several times as the LL can take a several micro/miliseconds to initialize and we may be too fast
		// after these sysctls
		for i := 0; i < 10; i++ {
			// No need to add a dummy next hop route as the host veth device will already have an IPv6
			// link local address that can be used as a next hop.
			// Just fetch the address of the host end of the veth and use it as the next hop.
			addresses, err := s.vpp.AddrList(swIfIndex, isv6)
			if err != nil {
				return nil, errors.Wrapf(err, "Error listing v6 addresses for the vpp side of the TAP")
			}
			for _, address := range addresses {
				return address.IPNet.IP, nil
			}
			s.log.Infof("No IPv6 set on interface, retrying..")
			time.Sleep(500 * time.Millisecond)
		}
		s.log.Errorf("No Ipv6 found for interface after 10 tries")
		return getPodv6IPNet(swIfIndex).IP, nil
	} else {
		return getPodv4IPNet(swIfIndex).IP, nil
	}
}

func (s *Server) announceLocalAddress(addr *net.IPNet, isWithdrawal bool) {
	s.routingServer.AnnounceLocalAddress(addr, isWithdrawal)
	s.servicesServer.AnnounceLocalAddress(addr, isWithdrawal)
}

func (s *Server) announceContainerInterface(swIfIndex uint32, isWithdrawal bool) {
	s.servicesServer.AnnounceContainerInterface(swIfIndex, isWithdrawal)
}

func (s *Server) configureNamespaceSideTap(args *pb.AddRequest, swIfIndex uint32, contTapName string, contTapMac *string) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contTap, err := netlink.LinkByName(contTapName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup %q: %v", contTapName, err)
		}

		// Fetch the MAC from the container tap. This is needed by Calico.
		*contTapMac = contTap.Attrs().HardwareAddr.String()
		s.log.WithField("MAC", *contTapMac).Debug("Found MAC for container tap")

		// Do the per-IP version set-up.  Add gateway routes etc.
		hasv4, hasv6 := getIpFamilies(args)
		if hasv4 {
			s.log.Infof("Tap %d in NS has v4", swIfIndex)
			// Add static neighbor entry for the VPP side of the tap
			hardwareAddr, err := net.ParseMAC(config.VppSideMacAddressString)
			if err != nil {
				return errors.Wrapf(err, "Unable to parse mac: %s", config.VppSideMacAddressString)
			}
			vppIPNet := getPodv4IPNet(swIfIndex)
			err = netlink.NeighAdd(&netlink.Neigh{
				LinkIndex:    contTap.Attrs().Index,
				Family:       netlink.FAMILY_V4,
				State:        netlink.NUD_PERMANENT,
				IP:           vppIPNet.IP,
				HardwareAddr: hardwareAddr,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add static neighbor entry in the container: %v", err)
			}

			// Add a connected route to a dummy next hop so that a default route can be set
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contTap.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       vppIPNet,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add route inside the container: %v", err)
			}
		}

		if hasv6 {
			s.log.Infof("Tap %d in NS has v6", swIfIndex)
			// Make sure ipv6 is enabled in the container/pod network namespace.
			// Without these sysctls enabled, interfaces will come up but they won't get a link local IPv6 address
			// which is required to add the default IPv6 route.
			if err = writeProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.all.disable_ipv6=0: %s", err)
			}

			if err = writeProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.default.disable_ipv6=0: %s", err)
			}

			if err = writeProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.lo.disable_ipv6=0: %s", err)
			}
			// FIXME : This isn't necessary if vpp can list link local ips
			// Add static neighbor entry for the VPP side of the tap
			hardwareAddr, err := net.ParseMAC(config.VppSideMacAddressString)
			if err != nil {
				return errors.Wrapf(err, "Unable to parse mac: %s", config.VppSideMacAddressString)
			}
			vppIPNet := getPodv6IPNet(swIfIndex)
			err = netlink.NeighAdd(&netlink.Neigh{
				LinkIndex:    contTap.Attrs().Index,
				Family:       netlink.FAMILY_V6,
				State:        netlink.NUD_PERMANENT,
				IP:           vppIPNet.IP,
				HardwareAddr: hardwareAddr,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add static neighbor entry in the container: %v", err)
			}

			s.log.Infof("Tap %d IP6 NS Route %+v", swIfIndex, vppIPNet)
			// Add a connected route to a dummy next hop so that a default route can be set
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contTap.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       vppIPNet,
			})
			if err != nil {
				return errors.Wrapf(err, "failed to add route inside the container: %v", err)
			}
		}

		for _, r := range args.GetContainerRoutes() {
			isv6 := r.GetIp().GetIsIpv6()
			if (isv6 && !hasv6) || (!isv6 && !hasv4) {
				s.log.WithField("route", r).Debug("Skipping route")
				continue
			}
			gw, err := s.getNamespaceSideGw(isv6, swIfIndex)
			if err != nil {
				return errors.Wrapf(err, "failed to get Next hop for route")
			}
			s.log.Infof("Tap %d IP6 NS Route/MAX %+v", swIfIndex, r.GetIp().GetIp())
			err = ip.AddRoute(&net.IPNet{
				IP:   r.GetIp().GetIp(),
				Mask: net.CIDRMask(int(r.GetPrefixLen()), getMaxCIDRLen(isv6)),
			}, gw, contTap)
			if err != nil {
				// TODO : in ipv6 '::' already exists
				s.log.Errorf("failed to add route for %v via %v : %+v", r, gw, err)
			}
		}

		// Now add the IPs to the container side of the tap.
		for _, addr := range args.GetContainerIps() {
			addr := &net.IPNet{
				IP:   addr.GetIp().GetIp().GetIp(),
				Mask: net.CIDRMask(int(addr.GetIp().GetPrefixLen()), getMaxCIDRLen(addr.GetIp().GetIp().GetIsIpv6())),
			}
			s.log.Infof("Tap %d IP6 NS Addr %+v", swIfIndex, addr)
			err = netlink.AddrAdd(contTap, &netlink.Addr{IPNet: addr})
			if err != nil {
				return errors.Wrapf(err, "failed to add IP addr to %q: %v", contTap, err)
			}
			s.announceLocalAddress(addr, false /* isWithdrawal */)
		}

		if err = s.configureContainerSysctls(args.GetSettings().GetAllowIpForwarding(), hasv4, hasv6); err != nil {
			return errors.Wrapf(err, "error configuring sysctls for the container netns, error: %s", err)
		}

		return nil
	}
}

func getIpFamilies(args *pb.AddRequest) (hasv4 bool, hasv6 bool) {
	for _, addr := range args.GetContainerIps() {
		if addr.GetIp().GetIp().GetIsIpv6() {
			hasv6 = true
		} else {
			hasv4 = true
		}
	}
	return hasv4, hasv6
}

// DoVppNetworking performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(args *pb.AddRequest) (ifName, contTapMac string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	contTapName := args.GetInterfaceName()
	netns := args.GetNetns()
	tapTag := netns + "-" + contTapName

	if args.GetDesiredHostInterfaceName() != "" {
		s.log.Warn("desired host side interface name passed, this is not supported with VPP, ignoring it")
	}

	s.log.Infof("creating container interface using VPP networking")
	s.log.Infof("setting tap tag to %s", tapTag)
	hasv4, hasv6 := getIpFamilies(args)

	vppSideMacAddress, err := net.ParseMAC(config.VppSideMacAddressString)
	if err != nil {
		return "", "", errors.Wrapf(err, "Unable to parse mac: %s", config.VppSideMacAddressString)
	}
	containerSideMacAddress, err := net.ParseMAC(config.ContainerSideMacAddressString)
	if err != nil {
		return "", "", errors.Wrapf(err, "Unable to parse mac: %s", config.ContainerSideMacAddressString)
	}

	// TODO: Clean up old tap if one is found with this tag
	swIfIndex, err := s.vpp.CreateTapV2(&types.TapV2{
		HostNamespace:  netns,
		HostIfName:     contTapName,
		Tag:            tapTag,
		MacAddress:     vppSideMacAddress,
		HostMacAddress: containerSideMacAddress,
	})
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error creating Tap")
	}
	s.log.Infof("Created tap with swIfIndex %d", swIfIndex)

	err = s.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "error setting new tap up")
	}

	// configure vpp side TAP
	if hasv4 {
		s.log.Infof("Add tap %d IP4 addr %+v", swIfIndex, getPodv4IPNet(swIfIndex))
		err = s.vpp.AddInterfaceAddress(swIfIndex, getPodv4IPNet(swIfIndex))
		if err != nil {
			return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error adding ip4 tap address")
		}
	}
	if hasv6 {
		s.log.Infof("Enabling tap %d IP6", swIfIndex)
		err = s.vpp.EnableInterfaceIP6(swIfIndex)
		if err != nil {
			return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error enabling ip6")
		}
		s.log.Infof("Add tap %d IP6 addr %+v", swIfIndex, getPodv6IPNet(swIfIndex))
		err = s.vpp.AddInterfaceAddress(swIfIndex, getPodv6IPNet(swIfIndex))
		if err != nil {
			return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error adding ip6 tap address")
		}
	}

	err = ns.WithNetNSPath(netns, s.configureNamespaceSideTap(args, swIfIndex, contTapName, &contTapMac))
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "Error creating or configuring tap")
	}

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = s.SetupVppRoutes(swIfIndex, args.GetContainerIps())
	if err != nil {
		return "", "", s.tapErrorCleanup(contTapName, netns, err, "error adding vpp side routes for interface: %s", tapTag)
	}

	s.announceContainerInterface(swIfIndex, false /* isWithdrawal */)

	s.log.Infof("tap setup complete")
	return swIfIdxToIfName(swIfIndex), contTapMac, err
}

func (s *Server) delVppInterfaceHandleRoutes(swIfIndex uint32, isIPv6 bool) error {
	// Delete neighbor entries. Is it really necessary?
	err, neighbors := s.vpp.GetInterfaceNeighbors(swIfIndex, isIPv6)
	if err != nil {
		return errors.Wrap(err, "GetInterfaceNeighbors errored")
	}
	for _, neighbor := range neighbors {
		err = s.vpp.DelNeighbor(&neighbor)
		if err != nil {
			s.log.Warnf("error deleting neighbor entry from VPP: %v", err)
		}
	}

	// Delete connected routes
	// TODO: Make TableID configurable?
	routes, err := s.vpp.GetRoutes(0, isIPv6)
	if err != nil {
		return errors.Wrap(err, "GetRoutes errored")
	}
	for _, route := range routes {
		// Filter routes we don't want to delete
		if route.SwIfIndex != swIfIndex {
			continue // Routes on other interfaces
		}
		maskSize, _ := route.Dst.Mask.Size()
		if isIPv6 {
			if maskSize != 128 {
				continue
			}
			if bytes.Equal(route.Dst.IP[0:2], []uint8{0xfe, 0x80}) {
				continue // Link locals
			}
		} else {
			if maskSize != 32 {
				continue
			}
			if bytes.Equal(route.Dst.IP[0:2], []uint8{169, 254}) {
				continue // Addresses configured on VPP side
			}
		}

		err = s.vpp.RouteDel(&route)
		if err != nil {
			s.log.Warnf("error deleting route %+v from VPP: %v", route, err)
		}
	}
	return nil
}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func (s *Server) DelVppInterface(args *pb.DelRequest) error {
	contIfName := args.GetInterfaceName()
	netns := args.GetNetns()
	s.log.Infof("deleting container interface using VPP networking, netns: %s, interface: %s", netns, contIfName)

	// Only try to delete the device if a namespace was passed in.
	if netns == "" {
		s.log.Infof("no netns passed, skipping")
		return nil
	}

	devErr := ns.WithNetNSPath(netns, func(_ ns.NetNS) error {
		dev, err := netlink.LinkByName(contIfName)
		if err != nil {
			return err
		}
		addresses, err := netlink.AddrList(dev, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, addr := range addresses {
			s.log.Debugf("Found address %s on interface, scope %d", addr.IP.String(), addr.Scope)
			if addr.Scope == unix.RT_SCOPE_LINK {
				continue
			}
			s.announceLocalAddress(&net.IPNet{IP: addr.IP, Mask: addr.Mask}, true /* isWithdrawal */)
		}
		return nil
	})
	if devErr != nil {
		switch devErr.(type) {
		case netlink.LinkNotFoundError:
			s.log.Infof("Device to delete not found")
			return nil
		default:
			s.log.Warnf("error withdrawing interface addresses: %v", devErr)
			return errors.Wrap(devErr, "error withdrawing interface addresses")
		}

	}

	tag := netns + "-" + contIfName
	s.log.Debugf("looking for tag %s, len %d", tag, len(tag))
	err, swIfIndex := s.vpp.SearchInterfaceWithTag(tag)
	if err != nil {
		return errors.Wrapf(err, "error searching interface with tag %s", tag)
	}

	s.log.Infof("found matching VPP tap interface")
	err = s.vpp.InterfaceAdminDown(swIfIndex)
	if err != nil {
		return errors.Wrap(err, "InterfaceAdminDown errored")
	}

	err = s.delVppInterfaceHandleRoutes(swIfIndex, true /* isIp6 */)
	if err != nil {
		return errors.Wrap(err, "Error deleting ip6 routes")
	}
	err = s.delVppInterfaceHandleRoutes(swIfIndex, false /* isIp6 */)
	if err != nil {
		return errors.Wrap(err, "Error deleting ip4 routes")
	}

	s.announceContainerInterface(swIfIndex, true /* isWithdrawal */)
	// Delete tap
	err = s.vpp.DelTap(swIfIndex)
	if err != nil {
		return errors.Wrap(err, "tap deletion failed")
	}
	s.log.Infof("tap %d deletion complete", swIfIndex)

	return nil
}
