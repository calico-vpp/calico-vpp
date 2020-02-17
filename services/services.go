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

package services

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/calico-vpp/calico-vpp/config"
	vppip "github.com/calico-vpp/calico-vpp/vpp-1908-api/ip"
	"github.com/calico-vpp/calico-vpp/vpp_client"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var (
	endpointStore cache.Store
	serviceStore  cache.Store
	endpointStop  chan struct{}
	serviceStop   chan struct{}
	log           *logrus.Entry
	vpp           *vpp_client.VppInterface
)

func GracefulStop() {
	close(endpointStop)
	close(serviceStop)
}

func AnnounceContainerInterface(v *vpp_client.VppInterface, swIfIndex uint32) error {
	return v.AddNat44OutsideInterface(swIfIndex)
}

func WithdrawContainerInterface(v *vpp_client.VppInterface, swIfIndex uint32) error {
	return v.DelNat44OutsideInterface(swIfIndex)
}

func getTargetPort(sPort v1.ServicePort) (int32, error) {
	tp := sPort.TargetPort
	if tp.Type == intstr.Int {
		if tp.IntVal == 0 {
			// Unset targetport
			return sPort.Port, nil
		} else {
			return tp.IntVal, nil
		}
	} else {
		return 0, fmt.Errorf("Unsupported string type for service port: %+v", sPort)
	}
}

func getServicePortProto(proto v1.Protocol) vppip.IPProto {
	switch proto {
	case v1.ProtocolUDP:
		return vppip.IP_API_PROTO_UDP
	case v1.ProtocolSCTP:
		return vppip.IP_API_PROTO_SCTP
	case v1.ProtocolTCP:
		return vppip.IP_API_PROTO_TCP
	default:
		return vppip.IP_API_PROTO_TCP
	}
}

func doServiceNat(s *v1.Service, ep *v1.Endpoints, isAdd bool) (err error) {
	if s == nil {
		return fmt.Errorf("nil service, cannot process")
	}
	if ep == nil {
		return fmt.Errorf("nil endpoint, cannot process")
	}

	if s.Spec.Type != v1.ServiceTypeClusterIP {
		return nil
	}
	if net.ParseIP(s.Spec.ClusterIP) == nil {
		log.Debugf("Service %s/%s has no IP, skipping", s.Namespace, s.Name)
		return nil
	}

	if isAdd {
		err = vpp.AddNat44Address(s.Spec.ClusterIP)
		if err != nil {
			return errors.Wrap(err, "error adding nat44 address")
		}
		err = vpp.AddNat44InsideInterface(config.DataInterfaceSwIfIndex)
		if err != nil {
			return errors.Wrap(err, "error adding nat44 physical interface")
		}
	}

	// For each port, build list of backends and add to VPP
	for _, servicePort := range s.Spec.Ports {
		var IPs []string
		for _, set := range ep.Subsets {
			// Check if this subset exposes the port we're interested in
			for _, port := range set.Ports {
				if servicePort.Name == port.Name {
					for _, addr := range set.Addresses {
						IPs = append(IPs, addr.IP)
					}
					break
				}
			}
		}
		log.Debugf("%d backends found for service %s/%s port %s", len(IPs), s.Namespace, s.Name, servicePort.Name)
		if len(IPs) == 0 {
			continue
		}
		targetPort, err := getTargetPort(servicePort)
		if err != nil {
			log.Warnf("Error determinig target port: %v", err)
			continue
		}
		if isAdd {
			err = vpp.AddNat44LB(s.Spec.ClusterIP, getServicePortProto(servicePort.Protocol), servicePort.Port, IPs, targetPort)
			if err != nil {
				return errors.Wrap(err, "error adding nat44 lb config")
			}
		} else {
			err = vpp.DelNat44LB(s.Spec.ClusterIP, getServicePortProto(servicePort.Protocol), servicePort.Port, len(IPs))
			if err != nil {
				return errors.Wrap(err, "error deleting nat44 lb config")
			}
		}
	}

	if !isAdd {
		err = vpp.DelNat44Address(s.Spec.ClusterIP)
		if err != nil {
			return errors.Wrap(err, "error deleting nat44 address")
		}
	}
	return nil
}

func addServiceNat(s *v1.Service, ep *v1.Endpoints) error {
	return doServiceNat(s, ep, true)
}

func delServiceNat(s *v1.Service, ep *v1.Endpoints) error {
	return doServiceNat(s, ep, false)
}

func findMatchingService(ep *v1.Endpoints) *v1.Service {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(ep)
	if err != nil {
		log.Errorf("Error getting endpoint %+v key: %v", ep, err)
		return nil
	}
	s, found, err := serviceStore.GetByKey(key)
	if err != nil {
		log.Errorf("Error getting service %s: %v", key, err)
		return nil
	}
	if !found {
		log.Debugf("Service %s not found", key)
		return nil
	}
	return s.(*v1.Service)
}

func findMatchingEndpoint(s *v1.Service) *v1.Endpoints {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(s)
	if err != nil {
		log.Errorf("Error getting service %+v key: %v", s, err)
		return nil
	}
	ep, found, err := endpointStore.GetByKey(key)
	if err != nil {
		log.Errorf("Error getting endpoint %s: %v", key, err)
		return nil
	}
	if !found {
		log.Debugf("Endpoint %s not found", key)
		return nil
	}
	return ep.(*v1.Endpoints)
}

func endpointAdded(ep *v1.Endpoints) error {
	log.Debugf("New endpoint: %s/%s", ep.Namespace, ep.Name)
	s := findMatchingService(ep)
	if s == nil {
		// Wait for matching service to be added
		return nil
	}
	log.Debugf("Found matching service")
	return addServiceNat(s, ep)
}

func endpointModified(ep *v1.Endpoints, old *v1.Endpoints) error {
	log.Debugf("Endpoint %s/%s modified", ep.Namespace, ep.Name)
	s := findMatchingService(ep)
	if s == nil {
		// Wait for matching endpoint to be added
		return nil
	}
	log.Debugf("Found matching service")
	err := delServiceNat(s, old)
	if err != nil {
		log.Errorf("Deleting NAT config failed, trying to re-add anyway")
	}
	return addServiceNat(s, ep)
}

func endpointRemoved(ep *v1.Endpoints) error {
	log.Debugf("Deleted endpoint: %s/%s", ep.Namespace, ep.Name)
	s := findMatchingService(ep)
	if s == nil {
		// Matching service already removed
		return nil
	}
	log.Debugf("Found matching service")
	return delServiceNat(s, ep)
}

func serviceAdded(s *v1.Service) error {
	log.Debugf("New service: %s/%s", s.Namespace, s.Name)
	ep := findMatchingEndpoint(s)
	if ep == nil {
		// Wait for matching endpoint to be added
		return nil
	}
	log.Debugf("Found matching endpoint")
	return addServiceNat(s, ep)
}

func serviceModified(s *v1.Service, old *v1.Service) error {
	log.Debugf("Service %s/%s modified", s.Namespace, s.Name)
	ep := findMatchingEndpoint(s)
	if ep == nil {
		// Wait for matching endpoint to be added
		return nil
	}
	log.Debugf("Found matching endpoint")
	err := delServiceNat(old, ep)
	if err != nil {
		log.Errorf("Deleting NAT config failed, trying to re-add anyway")
	}
	return addServiceNat(s, ep)
}

func serviceRemoved(s *v1.Service) error {
	log.Debugf("Deleted service: %s/%s", s.Namespace, s.Name)
	ep := findMatchingEndpoint(s)
	if ep == nil {
		// Matching endpoint already removed
		return nil
	}
	log.Debugf("Found matching endpoint")
	return delServiceNat(s, ep)
}

func Run(v *vpp_client.VppInterface, l *logrus.Entry) {
	var err error
	var endpointInformer, serviceInformer cache.Controller
	var lock sync.Mutex

	log = l
	vpp = v

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	err = vpp.EnableNatForwarding()
	if err != nil {
		log.Errorf("cannot enable VPP NAT44 forwarding: %v", err)
		return
	}

	serviceListWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(),
		"services", "", fields.Everything())
	serviceStore, serviceInformer = cache.NewInformer(
		serviceListWatch,
		&v1.Service{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				lock.Lock()
				defer lock.Unlock()
				err := serviceAdded(obj.(*v1.Service))
				if err != nil {
					l.Errorf("serviceAdded errored: %s", err)
				}
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				lock.Lock()
				defer lock.Unlock()
				err := serviceModified(obj.(*v1.Service), old.(*v1.Service))
				if err != nil {
					l.Errorf("serviceModified errored: %s", err)
				}
			},
			DeleteFunc: func(obj interface{}) {
				lock.Lock()
				defer lock.Unlock()
				err := serviceRemoved(obj.(*v1.Service))
				if err != nil {
					l.Errorf("serviceRemoved errored: %s", err)
				}
			},
		})

	endpointListWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(),
		"endpoints", "", fields.Everything())
	endpointStore, endpointInformer = cache.NewInformer(
		endpointListWatch,
		&v1.Endpoints{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				lock.Lock()
				defer lock.Unlock()
				err := endpointAdded(obj.(*v1.Endpoints))
				if err != nil {
					l.Errorf("endpointAdded errored: %s", err)
				}
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				lock.Lock()
				defer lock.Unlock()
				err := endpointModified(obj.(*v1.Endpoints), old.(*v1.Endpoints))
				if err != nil {
					l.Errorf("endpointModified errored: %s", err)
				}
			},
			DeleteFunc: func(obj interface{}) {
				lock.Lock()
				defer lock.Unlock()
				err := endpointRemoved(obj.(*v1.Endpoints))
				if err != nil {
					l.Errorf("endpointRemoved errored: %s", err)
				}
			},
		})

	serviceStop = make(chan struct{})
	go serviceInformer.Run(serviceStop)

	endpointStop = make(chan struct{})
	go endpointInformer.Run(endpointStop)

	// Wait forever
	select {}
}
