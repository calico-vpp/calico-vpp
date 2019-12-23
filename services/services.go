package services

import (
	"net"
	"time"
	"errors"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"github.com/sirupsen/logrus"
	"github.com/vpp-calico/vpp-calico/vpp_client"

	vppapi "git.fd.io/govpp.git/api"
	"github.com/vpp-calico/vpp-calico/vpp-1908-api/nat"
	"github.com/vpp-calico/vpp-calico/vpp-1908-api/ip"
	"github.com/vpp-calico/vpp-calico/vpp-1908-api/interfaces"
)

var (
	ipSwIfIndexMap map[string]uint32
)

func GracefulStop() {
}

func parseIP4Address (address string) nat.IP4Address {
	var ip nat.IP4Address
	copy(ip[:], net.ParseIP(address).To4()[0:4])
	return ip
}

func vppAddNat44Address(
	ch vppapi.Channel,
	logger *logrus.Entry,
	isAdd bool,
	address string,
) (err error) {
	response := &nat.Nat44AddDelAddressRangeReply{}
	request := &nat.Nat44AddDelAddressRange{
		FirstIPAddress:   parseIP4Address(address),
		LastIPAddress:    parseIP4Address(address),
		VrfID:            0,
		IsAdd:            isAdd,
		Flags:            nat.NAT_IS_NONE,
	}
	err = ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		logger.Errorf("Nat44 address add failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func vppEnableNatForwarding(
	ch vppapi.Channel,
	logger *logrus.Entry,
) (err error) {
	response := &nat.Nat44ForwardingEnableDisableReply{}
	request := &nat.Nat44ForwardingEnableDisable{
		Enable:           true,
	}
	err = ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		logger.Errorf("Nat44 enable forwarding failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func vppAddNat44Interface(
	ch vppapi.Channel,
	logger *logrus.Entry,
	isAdd bool,
	flags nat.NatConfigFlags,
	swIfIndex uint32,
) (err error) {
	response := &nat.Nat44InterfaceAddDelFeatureReply{}
	request := &nat.Nat44InterfaceAddDelFeature{
		IsAdd:      isAdd,
		Flags:      flags,
		SwIfIndex:  nat.InterfaceIndex(swIfIndex),
	}
	err = ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		logger.Errorf("Nat44 add interface failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func vppAddNat44LBStaticMapping(
	ch vppapi.Channel,
	logger *logrus.Entry,
	isAdd bool,
	servicePort v1.ServicePort,
	externalAddr string,
	locals []nat.Nat44LbAddrPort,
) (err error) {
	var protocol ip.IPProto
    switch servicePort.Protocol {
    	case "UDP":
    		protocol = 0 /* SNAT_PROTOCOL_UDP */
    	default:
    		fallthrough
    	case "SCTP":
    		fallthrough
    	case "TCP":
    		protocol = 1 /* SNAT_PROTOCOL_TCP */
    }

	response := &nat.Nat44AddDelLbStaticMappingReply{}
	request := &nat.Nat44AddDelLbStaticMapping{
		IsAdd:              isAdd,
		Flags:              nat.NAT_IS_NONE,
		ExternalAddr:       parseIP4Address (externalAddr),
		ExternalPort:       uint16(servicePort.Port),
		Protocol:           uint8(protocol),
		Locals:             locals,
	}
	err = ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		logger.Errorf("Nat44 add LB static failed: %v %d", err, response.Retval)
		return err
	}
	return nil
}

func getSwIfIndexForName(ch vppapi.Channel, logger *logrus.Entry, name string) (err error, swIfIndex uint32) {
	request := &interfaces.SwInterfaceDump{
		SwIfIndex: interfaces.InterfaceIndex(^uint32(0)),
		// TODO: filter by name with NameFilter
	}
	reqCtx := ch.SendMultiRequest(request)
	for {
		response := &interfaces.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(response)
		if err != nil {
			logger.Errorf("SwInterfaceDump failed: %v", err)
			return err, 0
		}
		if stop {
			break
		}
		if response.InterfaceName == name {
			return nil, response.SwIfIndex
		}

	}
	logger.Errorf("Interface %s not found", name)
	return errors.New("Interface not found"), 0
}

func addServiceNat(client *kubernetes.Clientset, service *v1.Service, v *vpp_client.VppInterface, l *logrus.Entry) {
	l.Debugf("Adding service")
	var podIPs []string
	var pods *v1.PodList
	ch, err := v.GetChannel()
	if err != nil {
		l.Errorf("error opening VPP API channel")
		return
	}
	err = vppEnableNatForwarding(ch, l)
	if err != nil {
		l.Errorf("error Enabling forwarding")
		return
	}
	err = vppAddNat44Address(ch, l, true /* isAdd */, service.Spec.ClusterIP)
	if err != nil {
		l.Errorf("error adding nat44 address")
		return
	}
	// TODO : find phy swIfIndex with getSwIfIndexForName
	swIfIndex := uint32(1)
	err = vppAddNat44Interface (ch, l, true /* isAdd */, nat.NAT_IS_INSIDE, swIfIndex)
	if err != nil {
		l.Errorf("error adding nat44 physical interface")
		return
	}

    set := labels.Set(service.Spec.Selector)
    pods, err = client.CoreV1().Pods(service.ObjectMeta.Namespace).List(metav1.ListOptions{LabelSelector: set.AsSelector().String()})
    if err != nil {
		l.Errorf("error Listing pods with selector")
		return
	}

    for len(podIPs) < len(pods.Items) {
    	podIPs = nil
    	pods, err = client.CoreV1().Pods(service.ObjectMeta.Namespace).List(metav1.ListOptions{LabelSelector: set.AsSelector().String()})
    	if err != nil {
			l.Errorf("error Listing pods with selector")
			return
		}
		l.Errorf("For now %d IPs on %d pods", len(podIPs), len(pods.Items))
		time.Sleep(time.Second * 1) /* ugly pacing */
		for _, pod := range pods.Items {
        	if pod.Status.PodIP != "" {
        		podIPs = append(podIPs, pod.Status.PodIP)
        	} else {
				l.Errorf("No IP on pod %s", pod.ObjectMeta.Name)
        	}
		}
    }

	for _, swIfIndex := range ipSwIfIndexMap {
		vppAddNat44Interface (ch, l, true /* isAdd */, nat.NAT_IS_INSIDE, swIfIndex)
		vppAddNat44Interface (ch, l, true /* isAdd */, nat.NAT_IS_OUTSIDE, swIfIndex)
    }

	for _, servicePort := range service.Spec.Ports {
		var locals []nat.Nat44LbAddrPort
		var port int32
		switch servicePort.TargetPort.Type {
		case intstr.Int:
			port = servicePort.TargetPort.IntVal
		case intstr.String:
			fallthrough
		default:
			l.Debugf("Wrong port format")
			continue
		}
		l.Debugf("Go mapping %d -> %d", servicePort.Port, port)
		for _, podIP := range podIPs {
			l.Debugf("Adding local %s:%d", podIP, port)
			locals = append(locals, nat.Nat44LbAddrPort{
        		Addr:               parseIP4Address(podIP),
        		Port:               uint16(port),
        		Probability:        1,
        	})
		}

		vppAddNat44LBStaticMapping (ch, l, true /* isAdd */, servicePort, service.Spec.ClusterIP, locals)
	}
}

func AnnounceLocalAddress(addr net.IP, swIfIndex uint32) error {
    ipSwIfIndexMap[addr.String()] = swIfIndex
    return nil
}

func WithdrawLocalAddress(addr net.IP) error {
    delete(ipSwIfIndexMap, addr.String())
	return nil
}

func delServiceNat(service *v1.Service, v *vpp_client.VppInterface, l *logrus.Entry) {
	l.Debugf("Deleting service")
}

func Run(v *vpp_client.VppInterface, l *logrus.Entry) {
	var err error
	ipSwIfIndexMap = make(map[string]uint32)

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	listWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(),
		"services", "", fields.Everything())
	_, informer := cache.NewInformer(
		listWatch,
		&v1.Service{},
		4 * 1000 * 1000 * 1000, // 4 sec in ns
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addServiceNat(client, obj.(*v1.Service), v, l)
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				// l.Debugf("Updating service")
			},
			DeleteFunc: func(obj interface{}) {
				delServiceNat (obj.(*v1.Service), v, l)
			},
		})
	stop := make(chan struct{})
	defer close(stop)
	go informer.Run(stop)

	// Wait forever
	select {}
}
