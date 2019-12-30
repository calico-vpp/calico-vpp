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
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vpp-calico/vpp-calico/config"
	"github.com/vpp-calico/vpp-calico/vpp_client"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func getAllServicePodIPs(client *kubernetes.Clientset, l *logrus.Entry, service *v1.Service) (err error, podIPs []string) {
	var pods *v1.PodList
	set := labels.Set(service.Spec.Selector)
	for {
		pods, err = client.CoreV1().Pods(service.ObjectMeta.Namespace).List(metav1.ListOptions{LabelSelector: set.AsSelector().String()})
		if err != nil {
			return errors.Wrap(err, "error Listing pods with selector"), nil
		}
		podIPs = nil
		for _, pod := range pods.Items {
			if pod.Status.PodIP != "" {
				podIPs = append(podIPs, pod.Status.PodIP)
			}
		}
		if len(podIPs) == len(pods.Items) {
			return nil, podIPs
		}
		l.Errorf("For now %d IPs on %d pods", len(podIPs), len(pods.Items))
		time.Sleep(time.Second * 1) /* ugly pacing */
	}
	return nil, nil
}

func GracefulStop() {
	/* FIXME stop gracefully */
}

func addServiceNat(client *kubernetes.Clientset, service *v1.Service, v *vpp_client.VppInterface, l *logrus.Entry) (err error) {
	l.Debugf("Adding service")
	err = v.EnableNatForwarding()
	if err != nil {
		return errors.Wrap(err, "error enabling forwarding")
	}
	err = v.AddNat44Address(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "error adding nat44 address")
	}
	err = v.AddNat44InsideInterface(config.DataInterfaceSwIfIndex)
	if err != nil {
		return errors.Wrap(err, "error adding nat44 physical interface")
	}

	err, podIPs := getAllServicePodIPs(client, l, service)
	if err != nil {
		return errors.Wrap(err, "error getting podIPs")
	}

	for _, servicePort := range service.Spec.Ports {
		err := v.AddNat44LBStaticMapping(servicePort, service.Spec.ClusterIP, podIPs)
		if err != nil {
			return errors.Wrap(err, "Error adding static LB")
		}
	}
	return nil
}

func AnnounceContainerInterface(v *vpp_client.VppInterface, swIfIndex uint32) error {
	return v.AddNat44OutsideInterface(swIfIndex)
}

func WithdrawContainerInterface(v *vpp_client.VppInterface, swIfIndex uint32) error {
	return v.DelNat44OutsideInterface(swIfIndex)
}

func delServiceNat(client *kubernetes.Clientset, service *v1.Service, v *vpp_client.VppInterface, l *logrus.Entry) (err error) {
	l.Debugf("Deleting service")
	err, podIPs := getAllServicePodIPs(client, l, service)
	if err != nil {
		return errors.Wrap(err, "error getting podIPs")
	}

	for _, servicePort := range service.Spec.Ports {
		err := v.DelNat44LBStaticMapping(servicePort, service.Spec.ClusterIP, podIPs)
		if err != nil {
			return errors.Wrap(err, "Error deleting static LB")
		}
	}

	err = v.DelNat44Address(service.Spec.ClusterIP)
	if err != nil {
		return errors.Wrap(err, "error deleting nat44 address")
	}

	return nil
}

func Run(v *vpp_client.VppInterface, l *logrus.Entry) {
	var err error

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
		4*1000*1000*1000, // 4 sec in ns
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				err := addServiceNat(client, obj.(*v1.Service), v, l)
				if err != nil {
					l.Errorf("addServiceNat Errored %s", err)
				}
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				// l.Debugf("Updating service")
			},
			DeleteFunc: func(obj interface{}) {
				err := delServiceNat(client, obj.(*v1.Service), v, l)
				if err != nil {
					l.Errorf("delServiceNat Errored %s", err)
				}
			},
		})
	stop := make(chan struct{})
	defer close(stop)
	go informer.Run(stop)

	// Wait forever
	select {}
}
