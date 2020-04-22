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
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calico-vpp/calico-vpp/config"
	"github.com/calico-vpp/vpplink"
	"github.com/pkg/errors"
	calicocliv3 "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type ServiceProvider interface {
	Init() error
	AddNodePort(service *v1.Service, ep *v1.Endpoints) error
	DelNodePort(service *v1.Service, ep *v1.Endpoints) error
	UpdateNodePort(service *v1.Service, ep *v1.Endpoints) error
	UpdateClusterIP(service *v1.Service, ep *v1.Endpoints) error
	AddClusterIP(service *v1.Service, ep *v1.Endpoints) error
	DelClusterIP(service *v1.Service, ep *v1.Endpoints) error
	AnnounceLocalAddress(addr *net.IPNet, isWithdrawal bool) error
	AnnounceContainerInterface(swIfIndex uint32, isWithdrawal bool) error
}

type Server struct {
	t                 tomb.Tomb
	endpointStore     cache.Store
	serviceStore      cache.Store
	serviceInformer   cache.Controller
	endpointInformer  cache.Controller
	clientv3          calicocliv3.Interface
	nodeName          string
	nodeIp            net.IP
	nodeIpNet         *net.IPNet
	lock              sync.Mutex
	log               *logrus.Entry
	vpp               *vpplink.VppLink
	vppTapSwIfindex   uint32
	service44Provider ServiceProvider
	service66Provider ServiceProvider
}

func fetchVppTapSwifIndex() (swIfIndex uint32, err error) {
	for i := 0; i < 20; i++ {
		dat, err := ioutil.ReadFile(config.VppManagerTapIdxFile)
		if err == nil {
			idx, err := strconv.ParseInt(strings.TrimSpace(string(dat[:])), 10, 32)
			if err == nil && idx != -1 {
				return uint32(idx), nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return 0, errors.Errorf("Vpp-host tap not ready after 20 tries")
}

func NewServer(vpp *vpplink.VppLink, log *logrus.Entry) (*Server, error) {
	nodeName := os.Getenv(config.NODENAME)
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	calicoCliV3, err := calicocliv3.NewFromEnv()
	if err != nil {
		panic(err.Error())
	}
	swIfIndex, err := fetchVppTapSwifIndex()
	if err != nil {
		panic(err.Error())
	}
	server := Server{
		clientv3:        calicoCliV3,
		nodeName:        nodeName,
		vpp:             vpp,
		log:             log,
		vppTapSwIfindex: swIfIndex,
	}
	serviceListWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(),
		"services", "", fields.Everything())
	serviceStore, serviceInformer := cache.NewInformer(
		serviceListWatch,
		&v1.Service{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				server.lock.Lock()
				defer server.lock.Unlock()
				err := server.serviceAdded(obj.(*v1.Service))
				if err != nil {
					log.Errorf("serviceAdded errored: %s", err)
				}
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				server.lock.Lock()
				defer server.lock.Unlock()
				err := server.serviceModified(obj.(*v1.Service), old.(*v1.Service))
				if err != nil {
					log.Errorf("serviceModified errored: %s", err)
				}
			},
			DeleteFunc: func(obj interface{}) {
				server.lock.Lock()
				defer server.lock.Unlock()
				err := server.serviceRemoved(obj.(*v1.Service))
				if err != nil {
					log.Errorf("serviceRemoved errored: %s", err)
				}
			},
		})

	endpointListWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(),
		"endpoints", "", fields.Everything())
	endpointStore, endpointInformer := cache.NewInformer(
		endpointListWatch,
		&v1.Endpoints{},
		60*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				server.lock.Lock()
				defer server.lock.Unlock()
				err := server.endpointAdded(obj.(*v1.Endpoints))
				if err != nil {
					log.Errorf("endpointAdded errored: %s", err)
				}
			},
			UpdateFunc: func(old interface{}, obj interface{}) {
				server.lock.Lock()
				defer server.lock.Unlock()
				err := server.endpointModified(obj.(*v1.Endpoints), old.(*v1.Endpoints))
				if err != nil {
					log.Errorf("endpointModified errored: %s", err)
				}
			},
			DeleteFunc: func(obj interface{}) {
				server.lock.Lock()
				defer server.lock.Unlock()
				err := server.endpointRemoved(obj.(*v1.Endpoints))
				if err != nil {
					log.Errorf("endpointRemoved errored: %s", err)
				}
			},
		})

	server.endpointStore = endpointStore
	server.serviceStore = serviceStore
	server.serviceInformer = serviceInformer
	server.endpointInformer = endpointInformer

	server.service44Provider = newService44Provider(&server)
	server.service66Provider = newService66Provider(&server)
	return &server, nil
}

func (s *Server) getNodeIP() (ip net.IP, ipNet *net.IPNet, err error) {
	if s.nodeIp == nil {
		node, err := s.clientv3.Nodes().Get(context.Background(), s.nodeName, options.GetOptions{})
		if err != nil {
			return nil, nil, errors.Wrap(err, "error getting node config")
		}
		ip, ipNet, err = net.ParseCIDR(node.Spec.BGP.IPv4Address)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "error parsing node IPv4 network: %s", node.Spec.BGP.IPv4Address)
		}
		s.nodeIp = ip
		s.nodeIpNet = ipNet
	}
	return s.nodeIp, s.nodeIpNet, nil
}

func (s *Server) findMatchingService(ep *v1.Endpoints) *v1.Service {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(ep)
	if err != nil {
		s.log.Errorf("Error getting endpoint %+v key: %v", ep, err)
		return nil
	}
	service, found, err := s.serviceStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting service %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Service %s not found", key)
		return nil
	}
	return service.(*v1.Service)
}

func (s *Server) findMatchingEndpoint(service *v1.Service) *v1.Endpoints {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(service)
	if err != nil {
		s.log.Errorf("Error getting service %+v key: %v", service, err)
		return nil
	}
	ep, found, err := s.endpointStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting endpoint %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Endpoint %s not found", key)
		return nil
	}
	return ep.(*v1.Endpoints)
}

func (s *Server) endpointAdded(ep *v1.Endpoints) error {
	s.log.Debugf("New endpoint: %s/%s", ep.Namespace, ep.Name)
	service := s.findMatchingService(ep)
	if service == nil {
		// Wait for matching service to be added
		return nil
	}
	s.log.Debugf("Found matching service")
	return s.AddServiceNat(service, ep)
}

func (s *Server) endpointModified(ep *v1.Endpoints, old *v1.Endpoints) error {
	// s.log.Debugf("Endpoint %s/%s modified", ep.Namespace, ep.Name)
	service := s.findMatchingService(ep)
	if service == nil {
		// Wait for matching endpoint to be added
		return nil
	}
	s.log.Debugf("Found matching service")
	return s.UpdateServiceNat(service, ep)
	// err := s.DelServiceNat(service, old)
	// if err != nil {
	// 	s.log.Errorf("Deleting NAT config failed, trying to re-add anyway")
	// }
	// return s.AddServiceNat(service, ep)
}

func (s *Server) endpointRemoved(ep *v1.Endpoints) error {
	s.log.Debugf("Deleted endpoint: %s/%s", ep.Namespace, ep.Name)
	service := s.findMatchingService(ep)
	if service == nil {
		// Matching service already removed
		return nil
	}
	s.log.Debugf("Found matching service")
	return s.DelServiceNat(service, ep)
}

func (s *Server) serviceAdded(service *v1.Service) error {
	s.log.Debugf("New service: %s/%s", service.Namespace, service.Name)
	ep := s.findMatchingEndpoint(service)
	if ep == nil {
		// Wait for matching endpoint to be added
		return nil
	}
	s.log.Debugf("Found matching endpoint")
	return s.AddServiceNat(service, ep)
}

func (s *Server) serviceModified(service *v1.Service, old *v1.Service) error {
	// s.log.Debugf("Service %s/%s modified", service.Namespace, service.Name)
	ep := s.findMatchingEndpoint(service)
	if ep == nil {
		// Wait for matching endpoint to be added
		return nil
	}
	s.log.Debugf("Found matching endpoint")
	return s.UpdateServiceNat(old, ep)
}

func (s *Server) serviceRemoved(service *v1.Service) error {
	s.log.Debugf("Deleted service: %s/%s", service.Namespace, service.Name)
	ep := s.findMatchingEndpoint(service)
	if ep == nil {
		// Matching endpoint already removed
		return nil
	}
	s.log.Debugf("Found matching endpoint")
	return s.DelServiceNat(service, ep)
}

func (s *Server) Serve() {
	err := s.vpp.EnableNatForwarding()
	if err != nil {
		s.log.Errorf("cannot enable VPP NAT44 forwarding")
		s.log.Fatal(err)
	}
	s.service44Provider.Init()
	if err != nil {
		s.log.Errorf("cannot init service44Provider forwarding")
		s.log.Fatal(err)
	}
	s.service66Provider.Init()
	if err != nil {
		s.log.Errorf("cannot init service66Provider forwarding")
		s.log.Fatal(err)
	}
	s.t.Go(func() error { s.serviceInformer.Run(s.t.Dying()); return nil })
	s.t.Go(func() error { s.endpointInformer.Run(s.t.Dying()); return nil })
	<-s.t.Dying()
}

func (s *Server) Stop() {
	s.t.Kill(errors.Errorf("GracefulStop"))
}
