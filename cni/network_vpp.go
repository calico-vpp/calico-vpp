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
	"github.com/calico-vpp/calico-vpp/routing"
	"github.com/calico-vpp/calico-vpp/services"
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
func SetupVppRoutes(v *vpplink.VppLink, logger *logrus.Entry, swIfIndex uint32, ipConfigs []*pb.IPConfig) error {
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
		err := v.RouteAdd(&types.Route{
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
		err = v.AddNeighbor(&types.Neighbor{
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

func tapErrorCleanup(v *vpplink.VppLink, contTapName string, netns string, err error, msg string, args ...interface{}) error {
	logger.Errorf("Error creating or configuring tap: %s", err)
	delErr := delVppInterface(v, logger.WithFields(logrus.Fields{"cleanup": true}), &pb.DelRequest{
		InterfaceName: contTapName,
		Netns:         netns,
	})
	if delErr != nil {
		logger.Errorf("Error deleting tap on error %+v", delErr)
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

func getNamespaceSideGw(v *vpplink.VppLink, isv6 bool, swIfIndex uint32) (gwIp net.IP, err error) {
	if isv6 {
		// Retry several times as the LL can take a several micro/miliseconds to initialize and we may be too fast
		// after these sysctls
		for i := 0; i < 10; i++ {
			// No need to add a dummy next hop route as the host veth device will already have an IPv6
			// link local address that can be used as a next hop.
			// Just fetch the address of the host end of the veth and use it as the next hop.
			addresses, err := vpp.AddrList(swIfIndex, isv6)
			if err != nil {
				return nil, errors.Wrapf(err, "Error listing v6 addresses for the vpp side of the TAP")
			}
			for _, address := range addresses {
				return address.IPNet.IP, nil
			}
			logger.Infof("No IPv6 set on interface, retrying..")
			time.Sleep(500 * time.Millisecond)
		}
		logger.Errorf("No Ipv6 found for interface after 10 tries")
		return getPodv6IPNet(swIfIndex).IP, nil
	} else {
		return getPodv4IPNet(swIfIndex).IP, nil
	}
}

func configureNamespaceSideTap(v *vpplink.VppLink, args *pb.AddRequest, swIfIndex uint32, contTapName string, contTapMac *string) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contTap, err := netlink.LinkByName(contTapName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup %q: %v", contTapName, err)
		}

		// Fetch the MAC from the container tap. This is needed by Calico.
		*contTapMac = contTap.Attrs().HardwareAddr.String()
		logger.WithField("MAC", *contTapMac).Debug("Found MAC for container tap")

		// Do the per-IP version set-up.  Add gateway routes etc.
		hasv4, hasv6 := getIpFamilies(args)
		if hasv4 {
			logger.Infof("Tap %d in NS has v4", swIfIndex)
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
			logger.Infof("Tap %d in NS has v6", swIfIndex)
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

			logger.Infof("Tap %d IP6 NS Route %+v", swIfIndex, vppIPNet)
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
				logger.WithField("route", r).Debug("Skipping route")
				continue
			}
			gw, err := getNamespaceSideGw(v, isv6, swIfIndex)
			if err != nil {
				return errors.Wrapf(err, "failed to get Next hop for route")
			}
			logger.Infof("Tap %d IP6 NS Route/MAX %+v", swIfIndex, r.GetIp().GetIp())
			err = ip.AddRoute(&net.IPNet{
				IP:   r.GetIp().GetIp(),
				Mask: net.CIDRMask(int(r.GetPrefixLen()), getMaxCIDRLen(isv6)),
			}, gw, contTap)
			if err != nil {
				// TODO : in ipv6 '::' already exists
				logger.Errorf("failed to add route for %v via %v : %+v", r, gw, err)
			}
		}

		// Now add the IPs to the container side of the tap.
		for _, addr := range args.GetContainerIps() {
			addr := &net.IPNet{
				IP:   addr.GetIp().GetIp().GetIp(),
				Mask: net.CIDRMask(int(addr.GetIp().GetPrefixLen()), getMaxCIDRLen(addr.GetIp().GetIp().GetIsIpv6())),
			}
			logger.Infof("Tap %d IP6 NS Addr %+v", swIfIndex, addr)
			err = netlink.AddrAdd(contTap, &netlink.Addr{IPNet: addr})
			if err != nil {
				return errors.Wrapf(err, "failed to add IP addr to %q: %v", contTap, err)
			}
			err = routing.AnnounceLocalAddress(*addr)
			if err != nil {
				return errors.Wrap(err, "failed to announce address")
			}
		}

		if err = configureContainerSysctls(logger, args.GetSettings().GetAllowIpForwarding(), hasv4, hasv6); err != nil {
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
func addVppInterface(v *vpplink.VppLink, logger *logrus.Entry, args *pb.AddRequest) (ifName, contTapMac string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	contTapName := args.GetInterfaceName()
	netns := args.GetNetns()
	tapTag := netns + "-" + contTapName

	if args.GetDesiredHostInterfaceName() != "" {
		logger.Warn("desired host side interface name passed, this is not supported with VPP, ignoring it")
	}

	logger.Infof("creating container interface using VPP networking")
	logger.Infof("setting tap tag to %s", tapTag)
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
	swIfIndex, err := v.CreateTapV2(&types.TapV2{
		HostNamespace:  netns,
		HostIfName:     contTapName,
		Tag:            tapTag,
		MacAddress:     vppSideMacAddress,
		HostMacAddress: containerSideMacAddress,
	})
	if err != nil {
		return "", "", tapErrorCleanup(v, contTapName, netns, err, "Error creating Tap")
	}
	logger.Infof("Created tap with swIfIndex %d", swIfIndex)

	err = v.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return "", "", tapErrorCleanup(v, contTapName, netns, err, "error setting new tap up")
	}

	// configure vpp side TAP
	if hasv4 {
		logger.Infof("Add tap %d IP4 addr %+v", swIfIndex, getPodv4IPNet(swIfIndex))
		err = v.AddInterfaceAddress(swIfIndex, getPodv4IPNet(swIfIndex))
		if err != nil {
			return "", "", tapErrorCleanup(v, contTapName, netns, err, "Error adding ip4 tap address")
		}
	}
	if hasv6 {
		logger.Infof("Enabling tap %d IP6", swIfIndex)
		err = v.EnableInterfaceIP6(swIfIndex)
		if err != nil {
			return "", "", tapErrorCleanup(v, contTapName, netns, err, "Error enabling ip6")
		}
		logger.Infof("Add tap %d IP6 addr %+v", swIfIndex, getPodv6IPNet(swIfIndex))
		err = v.AddInterfaceAddress(swIfIndex, getPodv6IPNet(swIfIndex))
		if err != nil {
			return "", "", tapErrorCleanup(v, contTapName, netns, err, "Error adding ip6 tap address")
		}
	}

	err = ns.WithNetNSPath(netns, configureNamespaceSideTap(v, args, swIfIndex, contTapName, &contTapMac))
	if err != nil {
		return "", "", tapErrorCleanup(v, contTapName, netns, err, "Error creating or configuring tap")
	}

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = SetupVppRoutes(v, logger, swIfIndex, args.GetContainerIps())
	if err != nil {
		return "", "", tapErrorCleanup(v, contTapName, netns, err, "error adding vpp side routes for interface: %s", tapTag)
	}

	err = services.AnnounceContainerInterface(v, swIfIndex)
	if err != nil {
		return "", "", tapErrorCleanup(v, contTapName, netns, err, "failed to announce address to services")
	}

	logger.Infof("tap setup complete")
	return swIfIdxToIfName(swIfIndex), contTapMac, err
}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func delVppInterface(v *vpplink.VppLink, logger *logrus.Entry, args *pb.DelRequest) error {
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
			// TODO : what if nat isnt setup when we delete ? -> err
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
			err = v.DelNeighbor(&neighbor)
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
			if route.SwIfIndex != swIfIndex {
				continue // Routes on other interfaces
			}
			maskSize, _ := route.Dst.Mask.Size()
			if isIPv6 == 0 {
				if maskSize != 32 {
					continue
				}
				if bytes.Equal(route.Dst.IP[0:2], []uint8{169, 254}) {
					continue // Addresses configured on VPP side
				}
			}
			if isIPv6 == 1 {
				if maskSize != 128 {
					continue
				}
				if bytes.Equal(route.Dst.IP[0:2], []uint8{0xfe, 0x80}) {
					continue // Link locals
				}
			}
			err = v.RouteDel(&route)
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
