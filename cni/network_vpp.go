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

	vppip "github.com/vpp-calico/vpp-calico/vpp-1908-api/ip"
	"github.com/vpp-calico/vpp-calico/vpp_client"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	pb "github.com/vpp-calico/vpp-calico/cni/proto"
	"github.com/vpp-calico/vpp-calico/config"
	"github.com/vpp-calico/vpp-calico/routing"
	"github.com/vpp-calico/vpp-calico/services"
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
func configureContainerSysctls(logger *logrus.Entry, allowIPForwarding, hasIPv4, hasIPv6 bool) error {
	ipFwd := "0"
	if allowIPForwarding {
		ipFwd = "1"
	}
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasIPv4 {
		logger.Info("Configuring IPv4 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", ipFwd); err != nil {
			return err
		}
	}
	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasIPv6 {
		logger.Info("Configuring IPv6 forwarding")
		if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", ipFwd); err != nil {
			return err
		}
	}
	return nil
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func SetupVppRoutes(v *vpp_client.VppInterface, logger *logrus.Entry, swIfIndex uint32, ipConfigs []*pb.IPConfig) error {
	var address vppip.Address
	logger.Infof("Configuring VPP side routes")
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
		err := v.ReplaceRoute(isIPv4, ip, ip.IP, swIfIndex)
		if err != nil {
			return errors.Wrapf(err, "Cannot add route in VPP")
		}

		if isIPv4 {
			ip := [4]uint8{}
			copy(ip[:], ipAddr.GetIp().GetIp().GetIp())
			address = vppip.Address{
				Af: vppip.ADDRESS_IP4,
				Un: vppip.AddressUnionIP4(ip),
			}
		} else {
			ip := [16]uint8{}
			copy(ip[:], ipAddr.GetIp().GetIp().GetIp())
			address = vppip.Address{
				Af: vppip.ADDRESS_IP6,
				Un: vppip.AddressUnionIP6(ip),
			}
		}

		logrus.WithFields(logrus.Fields{"IP": ipAddr.GetIp()}).Debugf("CNI adding VPP route")
		neighbor := vppip.IPNeighbor{
			SwIfIndex:  swIfIndex,
			Flags:      vppip.IP_API_NEIGHBOR_FLAG_STATIC,
			MacAddress: config.ContainerSideMacAddress,
			IPAddress:  address,
		}
		err = v.AddNeighbor(neighbor)
		if err != nil {
			return errors.Wrapf(err, "Cannot add neighbor in VPP")
		}
	}
	return nil
}

// DoVppNetworking performs the networking for the given config and IPAM result
func addVppInterface(v *vpp_client.VppInterface, logger *logrus.Entry, args *pb.AddRequest) (ifName, contTapMac string, err error) {
	logger.Infof("creating container interface using VPP networking")

	// Select the first 11 characters of the containerID for the host veth.
	contTapName := args.GetInterfaceName()
	netns := args.GetNetns()
	tapTag := netns + "-" + contTapName
	var hasIPv4, hasIPv6 bool

	if args.GetDesiredHostInterfaceName() != "" {
		logger.Warn("desired host side interface name passed, this is not supported with VPP, ignoring it")
	}

	logger.Infof("setting tap tag to %s", tapTag)

	// Figure out whether we have IPv4 and/or IPv6 addresses.
	for _, addr := range args.GetContainerIps() {
		if addr.GetIp().GetIp().GetIsIpv6() {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}

	// TODO: Clean up old tap if one is found with this tag
	swIfIndex, vppIPAddr, err := v.CreateTap(netns, contTapName, tapTag, hasIPv6)
	logger.Infof("Created tap with sw_if_index %d err %v", swIfIndex, err)
	if err != nil {
		delVppInterface(v, logger.WithFields(logrus.Fields{"cleanup": true}), &pb.DelRequest{
			InterfaceName: contTapName,
			Netns:         netns,
		})
		return "", "", err
	}
	err = services.AnnounceContainerInterface(v, swIfIndex)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to announce address to services")
	}

	err = ns.WithNetNSPath(netns, func(hostNS ns.NetNS) error {
		contTap, err := netlink.LinkByName(contTapName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", contTapName, err)
			return err
		}

		// Fetch the MAC from the container tap. This is needed by Calico.
		contTapMac = contTap.Attrs().HardwareAddr.String()
		logger.WithField("MAC", contTapMac).Debug("Found MAC for container tap")

		// Do the per-IP version set-up.  Add gateway routes etc.
		if hasIPv4 {
			// Add static neighbor entry for the VPP side of the tap
			err := netlink.NeighAdd(
				&netlink.Neigh{
					LinkIndex:    contTap.Attrs().Index,
					Family:       netlink.FAMILY_V4,
					State:        netlink.NUD_PERMANENT,
					IP:           vppIPAddr,
					HardwareAddr: config.VppSideMacAddress[:],
				},
			)
			if err != nil {
				return fmt.Errorf("failed to add static neighbor entry in the container: %v", err)
			}

			// Add a connected route to a dummy next hop so that a default route can be set
			gwNet := &net.IPNet{IP: vppIPAddr, Mask: net.CIDRMask(32, 32)}
			err = netlink.RouteAdd(
				&netlink.Route{
					LinkIndex: contTap.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       gwNet,
				},
			)

			if err != nil {
				return fmt.Errorf("failed to add route inside the container: %v", err)
			}

			for _, r := range args.GetContainerRoutes() {
				if r.GetIp().GetIsIpv6() {
					logger.WithField("route", r).Debug("Skipping non-IPv4 route")
					continue
				}
				logger.WithField("route", r).Debug("Adding IPv4 route")
				if err = ip.AddRoute(&net.IPNet{
					IP:   r.GetIp().GetIp(),
					Mask: net.CIDRMask(int(r.GetPrefixLen()), 32),
				}, vppIPAddr, contTap); err != nil {
					return fmt.Errorf("failed to add IPv4 route for %v via %v: %v", r, vppIPAddr, err)
				}
			}
		}

		if hasIPv6 {
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

			// Retry several times as the LL can take a several micro/miliseconds to initialize and we may be too fast
			// after these sysctls
			var err error
			var addresses []netlink.Addr
			for i := 0; i < 10; i++ {
				// No need to add a dummy next hop route as the host veth device will already have an IPv6
				// link local address that can be used as a next hop.
				// Just fetch the address of the host end of the veth and use it as the next hop.

				// TODO: get VPP's link local v6
				// addresses, err = netlink.AddrList(hostVeth, netlink.FAMILY_V6)
				// if err != nil {
				// 	logger.Errorf("Error listing IPv6 addresses for the host side of the veth pair: %s", err)
				// }

				// if len(addresses) < 1 {
				// 	// If the hostVeth doesn't have an IPv6 address then this host probably doesn't
				// 	// support IPv6. Since a IPv6 address has been allocated that can't be used,
				// 	// return an error.
				// 	err = fmt.Errorf("failed to get IPv6 addresses for host side of the veth pair")
				// }
				// if err == nil {
				// 	break
				// }

				// logger.Infof("No IPv6 set on interface, retrying..")
				// time.Sleep(50 * time.Millisecond)
			}

			err = fmt.Errorf("IPv6 not supported at this time")
			if err != nil {
				return err
			}

			hostIPv6Addr := addresses[0].IP

			for _, r := range args.GetContainerRoutes() {
				if !r.GetIp().GetIsIpv6() {
					logger.WithField("route", r).Debug("Skipping non-IPv6 route")
					continue
				}
				logger.WithField("route", r).Debug("Adding IPv6 route")
				if err = ip.AddRoute(&net.IPNet{
					IP:   r.GetIp().GetIp(),
					Mask: net.CIDRMask(int(r.GetPrefixLen()), 128),
				}, hostIPv6Addr, contTap); err != nil {
					return fmt.Errorf("failed to add IPv6 route for %v via %v: %v", r, hostIPv6Addr, err)
				}
			}
		}

		// Now add the IPs to the container side of the tap.
		for _, addr := range args.GetContainerIps() {
			maskLen := 32
			if addr.GetIp().GetIp().GetIsIpv6() {
				maskLen = 128
			}
			addr := &net.IPNet{
				IP:   addr.GetIp().GetIp().GetIp(),
				Mask: net.CIDRMask(int(addr.GetIp().GetPrefixLen()), maskLen),
			}
			err = netlink.AddrAdd(contTap, &netlink.Addr{IPNet: addr})
			if err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", contTap, err)
			}
			err = routing.AnnounceLocalAddress(*addr)
			if err != nil {
				return errors.Wrap(err, "failed to announce address")
			}
		}

		if err = configureContainerSysctls(logger, args.GetSettings().GetAllowIpForwarding(), hasIPv4, hasIPv6); err != nil {
			return fmt.Errorf("error configuring sysctls for the container netns, error: %s", err)
		}

		return nil
	})

	if err != nil {
		logger.Errorf("Error creating or configuring tap: %s", err)
		delVppInterface(v, logger.WithFields(logrus.Fields{"cleanup": true}), &pb.DelRequest{
			InterfaceName: contTapName,
			Netns:         netns,
		})
		return "", "", err
	}

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = SetupVppRoutes(v, logger, swIfIndex, args.GetContainerIps())
	if err != nil {
		delVppInterface(v, logger.WithFields(logrus.Fields{"cleanup": true}), &pb.DelRequest{
			InterfaceName: contTapName,
			Netns:         netns,
		})
		return "", "", fmt.Errorf("error adding vpp side routes for interface: %s, error: %s", tapTag, err)
	}

	logger.Infof("tap setup complete")
	return swIfIdxToIfName(swIfIndex), contTapMac, err
}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func delVppInterface(v *vpp_client.VppInterface, logger *logrus.Entry, args *pb.DelRequest) error {
	contIfName := args.GetInterfaceName()
	netns := args.GetNetns()
	logger.Infof("deleting container interface using VPP networking, netns: %s, interface: %s", netns, contIfName)

	// Only try to delete the device if a namespace was passed in.
	if netns == "" {
		logger.Infof("no netns passed, skipping")
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
			logger.Debugf("Found address %s on interface, scope %d", addr.IP.String(), addr.Scope)
			if addr.Scope == unix.RT_SCOPE_LINK {
				continue
			}
			err = routing.WithdrawLocalAddress(net.IPNet{IP: addr.IP, Mask: addr.Mask})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if devErr != nil {
		switch devErr.(type) {
		case netlink.LinkNotFoundError:
			logger.Infof("Device to delete not found")
			return nil
		default:
			logger.Warnf("error withdrawing interface addresses: %v", devErr)
			return errors.Wrap(devErr, "error withdrawing interface addresses")
		}

	}

	tag := netns + "-" + contIfName
	logger.Debugf("looking for tag %s, len %d", tag, len(tag))
	err, swIfIndex := v.SearchInterfaceWithTag(tag)
	if err != nil {
		return errors.Wrapf(err, "error searching interface with tag %s", tag)
	}

	logger.Infof("found matching VPP tap interface")
	err = v.InterfaceAdminDown(swIfIndex)
	if err != nil {
		return errors.Wrap(err, "InterfaceAdminDown errored")
	}

	// Delete neighbor entries. Is it really necessary?
	for isIPv6 := uint8(0); isIPv6 <= 1; isIPv6++ {
		err, neighbors := v.GetInterfaceNeighbors(swIfIndex, isIPv6)
		if err != nil {
			return errors.Wrap(err, "GetInterfaceNeighbors errored")
		}
		for _, neighbor := range neighbors {
			err = v.DelNeighbor(neighbor)
			if err != nil {
				logger.Warnf("error deleting neighbor entry from VPP: %v", err)
			}
		}
	}

	// Delete connected routes
	for isIPv6 := uint8(0); isIPv6 <= 1; isIPv6++ {
		// TODO: Make TableID configurable?
		routes, err := v.GetRoutes(0, isIPv6)
		if err != nil {
			return errors.Wrap(err, "GetRoutes errored")
		}
		for _, route := range routes {
			// Filter routes we don't want to delete
			if route.NPaths != 1 || route.Paths[0].SwIfIndex != swIfIndex {
				continue // Routes on other interfaces
			}
			if isIPv6 == 0 {
				if route.Prefix.Len != 32 {
					continue
				}
				ip4 := route.Prefix.Address.Un.GetIP4()
				if bytes.Equal(ip4[0:2], []uint8{169, 254}) {
					continue // Addresses configured on VPP side
				}
			}
			if isIPv6 == 1 {
				if route.Prefix.Len != 128 {
					continue
				}
				ip6 := route.Prefix.Address.Un.GetIP6()
				if bytes.Equal(ip6[0:2], []uint8{0xfe, 0x80}) {
					continue // Link locals
				}
			}
			err = v.DelIPRoute(route)
			if err != nil {
				logger.Warnf("error deleting route %+v from VPP: %v", route, err)
			}
		}
	}

	err = services.WithdrawContainerInterface(v, swIfIndex)
	if err != nil {
		return errors.Wrap(err, "service WithdrawContainerInterface errored")
	}
	// Delete tap
	err = v.DelTap(swIfIndex)
	if err != nil {
		return errors.Wrap(err, "tap deletion failed")
	}
	logger.Infof("tap %d deletion complete", swIfIndex)

	return nil
}
