// Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"reflect"
	"sync"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	calicocli "github.com/projectcalico/libcalico-go/lib/client"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// contains returns true if the IPPool contains 'prefix'
func contains(pool model.IPPool, prefix string) (bool, error) {
	ip, prefixNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return false, err
	}
	poolCIDRLen, poolCIDRBits := pool.CIDR.Mask.Size()
	prefixLen, prefixBits := prefixNet.Mask.Size()
	return poolCIDRBits == prefixBits && pool.CIDR.Contains(ip) && prefixLen >= poolCIDRLen, nil
}

type ipamCache struct {
	mu            sync.RWMutex
	m             map[string]*model.IPPool
	client        *calicocli.Client
	updateHandler func(*ipPool) error
	ready         bool
	readyCond     *sync.Cond
}

// match checks whether we have an IP pool which contains the given prefix.
// If we have, it returns the pool.
func (c *ipamCache) match(prefix string) *ipPool {
	if !c.ready {
		c.readyCond.L.Lock()
		for !c.ready {
			c.readyCond.Wait()
		}
		c.readyCond.L.Unlock()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.m {
		if p.contain(prefix) {
			return p
		}
	}
	return nil
}

// update updates the internal map with IPAM updates when the update
// is new addtion to the map or changes the existing item, it calls
// updateHandler
func (c *ipamCache) update(pair model.KVPair, del bool) error {
	if reflect.TypeOf(pair.Value) != reflect.TypeOf(model.IPPool{}) {
		log.Panicf("unknown parameter type: %s", reflect.TypeOf(nodeEtcd))
	}
	pool := pair.Value.(model.IPPool)
	key := pair.Key.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("update ipam cache: %s, %v, %t", key, pool, del)

	existing := c.m[key]
	if del {
		delete(c.m, key)
		return nil
	} else if pool == existing {
		return nil
	}

	c.m[key] = pool

	if c.updateHandler != nil {
		return c.updateHandler(pool)
	}
	return nil
}

// sync synchronizes the IP pools stored under /calico/v1/ipam
func (c *ipamCache) sync() error {
	poolsList, err := c.client.Backend.List(context.Background(), model.IPPoolListOptions{}, "")
	if err != nil {
		return err
	}
	for _, pool := range poolsList.KVPairs {
		err := c.update(pool, false)
	}

	c.ready = true
	c.readyCond.Broadcast()

	startRevision := poolsList.Revision
	poolsWatcher, err := c.client.Backend.Watch(context.Background(), model.IPPoolListOptions{}, startRevision)
	if err != nil {
		return err
	}
	for update := range poolsWatcher.ResultChan() {
		del := false
		pair := update.New
		switch update.WatchEventType {
		case WatchError:
			return update.Error
		case WatchDeleted:
			del = true
			pair = update.Old
		case WatchAdded, WatchModified:
		}
		if err = c.update(pair, del); err != nil {
			return err
		}
	}
	return nil
}

// create new IPAM cache
func newIPAMCache(client *calicocli.Client, updateHandler func(*model.IPPool) error) *ipamCache {
	cond := sync.NewCond(&sync.Mutex{})
	return &ipamCache{
		m:             make(map[string]*ipPool),
		updateHandler: updateHandler,
		client:        client,
		readyCond:     cond,
	}
}
