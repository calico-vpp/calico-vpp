package cni

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/vpp-calico/vpp-calico/vpp-1908-api/interfaces"
	vppip "github.com/vpp-calico/vpp-calico/vpp-1908-api/ip"
	"github.com/vpp-calico/vpp-calico/vpp-1908-api/tapv2"

	vppapi "git.fd.io/govpp.git/api"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	pb "github.com/vpp-calico/vpp-calico/cni/proto"
	"github.com/vpp-calico/vpp-calico/routing"
	"github.com/vpp-calico/vpp-calico/services"
	"golang.org/x/sys/unix"
)

var (
	vppSideMacAddress       = [6]byte{2, 0, 0, 0, 0, 2}
	containerSideMacAddress = [6]byte{2, 0, 0, 0, 0, 1}
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

func createVppTap(
	logger *logrus.Entry,
	ch vppapi.Channel,
	ContNS string,
	ContIfName string,
	Tag string,
	EnableIp6 bool,
) (SwIfIndex uint32, vppIPAddress []byte, err error) {
	invalidIndex := ^uint32(0)
	response := &tapv2.TapCreateV2Reply{}
	request := &tapv2.TapCreateV2{
		// TODO check namespace len < 64?
		// TODO set MTU?
		ID:               ^uint32(0),
		HostNamespace:    []byte(ContNS),
		HostNamespaceSet: 1,
		HostIfName:       []byte(ContIfName),
		HostIfNameSet:    1,
		Tag:              []byte(Tag),
		MacAddress:       vppSideMacAddress[:],
		HostMacAddr:      containerSideMacAddress[:],
		HostMacAddrSet:   1,
	}
	logger.Debugf("Tap creation request: %+v", request)

	err = ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		logger.Errorf("Tap creation request failed")
		return invalidIndex, vppIPAddress, err
	}

	if response.Retval != 0 {
		logger.Errorf("Tap creation failed")
		return invalidIndex, vppIPAddress, fmt.Errorf("Vpp tap creation failed with code %d. Request: %+v", response.Retval, request)
	}

	logger.Infof("Tap creation successful. sw_if_index = %d", response.SwIfIndex)

	// Add VPP side fake address
	// TODO: Only if v4 is enabled
	// There is currently a hard limit in VPP to 1024 taps - so this should be safe
	vppIPAddress = []byte{169, 254, byte(response.SwIfIndex >> 8), byte(response.SwIfIndex)}

	addrAddRequest := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex:     response.SwIfIndex,
		IsAdd:         1,
		AddressLength: 32,
		Address:       vppIPAddress,
	}
	addrAddResponse := &interfaces.SwInterfaceAddDelAddressReply{}
	err = ch.SendRequest(addrAddRequest).ReceiveReply(addrAddResponse)
	if err != nil {
		logger.Errorf("Adding IP address failed: req %+v reply %+v", addrAddRequest, addrAddResponse)
		return invalidIndex, vppIPAddress, err
	}

	// Set interface up
	AdminUpRequest := &interfaces.SwInterfaceSetFlags{
		SwIfIndex:   response.SwIfIndex,
		AdminUpDown: 1,
	}
	AdminUpResponse := &interfaces.SwInterfaceSetFlagsReply{}
	err = ch.SendRequest(AdminUpRequest).ReceiveReply(AdminUpResponse)
	if err != nil {
		logger.Errorf("Setting interface up failed")
		return invalidIndex, vppIPAddress, err
	}

	// Add IPv6 neighbor entry if v6 is enabled

	if EnableIp6 {
		// TODO disable RA
		Ip6EnableRequest := &vppip.SwInterfaceIP6EnableDisable{
			SwIfIndex: response.SwIfIndex,
			Enable:    1,
		}
		Ip6EnableResponse := &vppip.SwInterfaceIP6EnableDisableReply{}
		err = ch.SendRequest(Ip6EnableRequest).ReceiveReply(Ip6EnableResponse)
		if err != nil {
			logger.Errorf("IPv6 enabling failed")
			return invalidIndex, vppIPAddress, err
		}
		// Compute a link local address from mac address, and set it

	}
	return response.SwIfIndex, vppIPAddress, err
}

// DoVppNetworking performs the networking for the given config and IPAM result
func addVppInterface(
	logger *logrus.Entry,
	args *pb.AddRequest,
) (ifName, contTapMac string, err error) {
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

	ch, err := vpp.GetChannel()
	if err != nil {
		return "", "", errors.Wrap(err, "error opening VPP API channel")
	}
	defer ch.Close()

	// TODO: Clean up old tap if one is found with this tag

	swIfIndex, vppIPAddr, err := createVppTap(logger, ch, netns, contTapName, tapTag, hasIPv6)
	logger.Infof("Created tap with sw_if_index %d err %v", swIfIndex, err)
	if err != nil {
		delVppInterface(logger.WithFields(logrus.Fields{"cleanup": true}), &pb.DelRequest{
			InterfaceName: contTapName,
			Netns:         netns,
		})
		return "", "", err
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
					HardwareAddr: vppSideMacAddress[:],
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
			err = services.AnnounceLocalAddress(addr.IP, swIfIndex)
			if err != nil {
				return errors.Wrap(err, "failed to announce address to services")
			}
		}

		if err = configureContainerSysctls(logger, args.GetSettings().GetAllowIpForwarding(), hasIPv4, hasIPv6); err != nil {
			return fmt.Errorf("error configuring sysctls for the container netns, error: %s", err)
		}

		return nil
	})

	if err != nil {
		logger.Errorf("Error creating or configuring tap: %s", err)
		delVppInterface(logger.WithFields(logrus.Fields{"cleanup": true}), &pb.DelRequest{
			InterfaceName: contTapName,
			Netns:         netns,
		})
		return "", "", err
	}

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = SetupVppRoutes(ch, swIfIndex, args.GetContainerIps(), logger)
	if err != nil {
		delVppInterface(logger.WithFields(logrus.Fields{"cleanup": true}), &pb.DelRequest{
			InterfaceName: contTapName,
			Netns:         netns,
		})
		return "", "", fmt.Errorf("error adding vpp side routes for interface: %s, error: %s", tapTag, err)
	}

	logger.Infof("tap setup complete")
	return swIfIdxToIfName(swIfIndex), contTapMac, err
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func SetupVppRoutes(ch vppapi.Channel, swIfIndex uint32, config []*pb.IPConfig, logger *logrus.Entry) error {
	logger.Infof("Configuring VPP side routes")
	// Go through all the IPs and add routes for each IP in the result.
	for _, ipAddr := range config {
		logger.Debugf("Adding one route to %+v", ipAddr)
		request := &vppip.IPRouteAddDel{
			IsAdd:       1,
			IsMultipath: 0,
			Route: vppip.IPRoute{
				TableID: 0,
				Paths: []vppip.FibPath{
					{
						SwIfIndex:  swIfIndex,
						TableID:    0,
						RpfID:      0,
						Weight:     1,
						Preference: 0,
						Type:       vppip.FIB_API_PATH_TYPE_NORMAL,
						Flags:      vppip.FIB_API_PATH_FLAG_NONE,
						Proto:      vppip.FIB_API_PATH_NH_PROTO_IP4,
					},
				},
			},
		}

		if !ipAddr.GetIp().GetIp().GetIsIpv6() {
			ip := [4]uint8{}
			copy(ip[:], ipAddr.GetIp().GetIp().GetIp())
			request.Route.Prefix = vppip.Prefix{
				Address: vppip.Address{
					Af: vppip.ADDRESS_IP4,
					Un: vppip.AddressUnionIP4(ip),
				},
				Len: 32,
			}
		} else {
			ip := [16]uint8{}
			copy(ip[:], ipAddr.GetIp().GetIp().GetIp())
			request.Route.Paths[0].Proto = vppip.FIB_API_PATH_NH_PROTO_IP6
			request.Route.Prefix = vppip.Prefix{
				Address: vppip.Address{
					Af: vppip.ADDRESS_IP6,
					Un: vppip.AddressUnionIP6(ip),
				},
				Len: 128,
			}
		}
		request.Route.Paths[0].Nh.Address = request.Route.Prefix.Address.Un

		response := &vppip.IPRouteAddDelReply{}

		logger.Debugf("Route add object: %+v", request)

		err := ch.SendRequest(request).ReceiveReply(response)
		if err != nil || response.Retval != 0 {
			return fmt.Errorf("Cannot add route in VPP: %v %d", err, response.Retval)
		}

		logrus.WithFields(logrus.Fields{"IP": ipAddr.GetIp()}).Debugf("CNI adding VPP route")

		// Adding neighbor entry
		neighAddRequest := &vppip.IPNeighborAddDel{
			IsAdd: 1,
			Neighbor: vppip.IPNeighbor{
				SwIfIndex:  swIfIndex,
				Flags:      vppip.IP_API_NEIGHBOR_FLAG_STATIC,
				MacAddress: containerSideMacAddress,
				IPAddress:  request.Route.Prefix.Address,
			},
		}
		neighAddReply := &vppip.IPNeighborAddDelReply{}
		err = ch.SendRequest(neighAddRequest).ReceiveReply(neighAddReply)
		if err != nil || neighAddReply.Retval != 0 {
			return fmt.Errorf("Cannot add neighbor in VPP: %v %d", err, neighAddReply.Retval)
		}
	}
	return nil
}

// CleanUpVPPNamespace deletes the devices in the network namespace.
func delVppInterface(logger *logrus.Entry, args *pb.DelRequest) error {
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
			err = services.WithdrawLocalAddress(addr.IP)
			if err != nil {
				return errors.Wrap(err, "failed to withdraw address from services")
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

	ch, err := vpp.GetChannel()
	if err != nil {
		return errors.Wrap(err, "error opening VPP API channel")
	}
	defer ch.Close()

	// First, find the right tap
	intfDumpRequest := &interfaces.SwInterfaceDump{
		//NameFilterValid: true,
		//NameFilter:      "tap",
	}
	tag := netns + "-" + contIfName
	logger.Debugf("looking for tag %s, len %d", tag, len(tag))
	intf := &interfaces.SwInterfaceDetails{}
	stream := ch.SendMultiRequest(intfDumpRequest)
	for {
		stop, err := stream.ReceiveReply(intf)
		if err != nil {
			logger.Errorf("error listing VPP interfaces: %v", err)
			return err
		}
		if stop {
			logger.Errorf("error: interface to delete not found")
			return fmt.Errorf("VPP Error: interface to delete not found")
		}
		intfTag := string(bytes.Trim([]byte(intf.Tag), "\x00"))
		logger.Debugf("found interface %d, tag: %s (len %d)", intf.SwIfIndex, intfTag, len(intfTag))
		if intfTag == tag {
			break
		}
	}

	logger.Infof("found matching VPP tap interface: %+v", intf)

	// Set interface down
	AdminDownRequest := &interfaces.SwInterfaceSetFlags{
		SwIfIndex:   intf.SwIfIndex,
		AdminUpDown: 0,
	}
	AdminDownResponse := &interfaces.SwInterfaceSetFlagsReply{}
	err = ch.SendRequest(AdminDownRequest).ReceiveReply(AdminDownResponse)
	if err != nil {
		logger.Errorf("setting interface down failed")
		return err
	}

	// Delete neighbor entries. Is it really necessary?
	for isIPv6 := uint8(0); isIPv6 <= 1; isIPv6++ {
		neighDumpRequest := &vppip.IPNeighborDump{
			SwIfIndex: intf.SwIfIndex,
			IsIPv6:    isIPv6,
		}
		neighDumpReply := &vppip.IPNeighborDetails{}
		stream := ch.SendMultiRequest(neighDumpRequest)
		neighbors := make([]vppip.IPNeighborAddDel, 0, 10)
		for {
			stop, err := stream.ReceiveReply(neighDumpReply)
			if err != nil {
				logger.Errorf("error listing VPP neighbors: %v", err)
				return err
			}
			if stop {
				break
			}
			neighbors = append(neighbors, vppip.IPNeighborAddDel{
				IsAdd:    0,
				Neighbor: neighDumpReply.Neighbor,
			})
		}
		for i := 0; i < len(neighbors); i++ {
			neighDelReply := &vppip.IPNeighborAddDelReply{}
			err = ch.SendRequest(&neighbors[i]).ReceiveReply(neighDelReply)
			if err != nil {
				logger.Warnf("failed to delete neighbor from VPP")
			}
			logger.Debugf("deleted neighbor %+v", neighbors[i])
		}
	}

	// Delete connected routes
	for isIPv6 := uint8(0); isIPv6 <= 1; isIPv6++ {
		routeDumpRequest := &vppip.IPRouteDump{
			Table: vppip.IPTable{
				TableID: 0, // TODO: Make configurable?
				IsIP6:   isIPv6,
			},
		}
		routeDumpReply := &vppip.IPRouteDetails{}
		stream := ch.SendMultiRequest(routeDumpRequest)
		routes := make([]vppip.IPRouteAddDel, 0, 10)
		for {
			stop, err := stream.ReceiveReply(routeDumpReply)
			if err != nil {
				logger.Errorf("error listing VPP routes: %v", err)
				return err
			}
			if stop {
				break
			}
			// Filter routes we don't want to delete
			if routeDumpReply.Route.NPaths != 1 || routeDumpReply.Route.Paths[0].SwIfIndex != intf.SwIfIndex {
				continue // Routes on other interfaces
			}
			if isIPv6 == 0 {
				if routeDumpReply.Route.Prefix.Len != 32 {
					continue
				}
				ip4 := routeDumpReply.Route.Prefix.Address.Un.GetIP4()
				if bytes.Equal(ip4[0:2], []uint8{169, 254}) {
					continue // Addresses configured on VPP side
				}
			}
			if isIPv6 == 1 {
				if routeDumpReply.Route.Prefix.Len != 128 {
					continue
				}
				ip6 := routeDumpReply.Route.Prefix.Address.Un.GetIP6()
				if bytes.Equal(ip6[0:2], []uint8{0xfe, 0x80}) {
					continue // Link locals
				}
			}
			routes = append(routes, vppip.IPRouteAddDel{
				IsAdd: 0,
				Route: routeDumpReply.Route,
			})
		}
		for i := 0; i < len(routes); i++ {
			routeDelReply := &vppip.IPRouteAddDelReply{}
			err = ch.SendRequest(&routes[i]).ReceiveReply(routeDelReply)
			if err != nil {
				logger.Warnf("failed to delete route from VPP")
			}
			logger.Debugf("deleted route %+v", routes[i])
		}
	}

	// Delete tap
	tapDeleteRequest := &tapv2.TapDeleteV2{
		SwIfIndex: intf.SwIfIndex,
	}
	tapDeleteReply := &tapv2.TapDeleteV2Reply{}
	err = ch.SendRequest(tapDeleteRequest).ReceiveReply(tapDeleteReply)
	if err != nil {
		logger.Errorf("failed to delete tap from VPP")
		return err
	}

	logger.Infof("tap %d deletion complete", intf.SwIfIndex)

	return nil
}
