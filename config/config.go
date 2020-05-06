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

package config

import (
	"fmt"
	"os"
	"strconv"
)

const (
	NODENAME               = "NODENAME"
	DataInterfaceSwIfIndex = uint32(1) // Assumption: the VPP config ensures this is true
	CNIServerSocket        = "/var/run/calico/cni-server.sock"
	VppAPISocket           = "/var/run/vpp/vpp-api.sock"
	VppManagerStatusFile   = "/var/run/vpp/vppmanagerstatus"
	VppManagerTapIdxFile   = "/var/run/vpp/vppmanagertap0"

	VppSideMacAddressString       = "02:00:00:00:00:02"
	ContainerSideMacAddressString = "02:00:00:00:00:01"

	TapRXQueuesEnvVar = "CALICOVPP_TAP_RX_QUEUES"
	TapGSOEnvVar      = "CALICOVPP_TAP_GSO_ENABLED"
)

var (
	TapRXQueues   = 1
	TapGSOEnabled = false
)

// LoadConfig loads the calico-vpp-agent configuration from the environment
func LoadConfig() (err error) {
	if conf := os.Getenv(TapRXQueuesEnvVar); conf != "" {
		queues, err := strconv.ParseInt(conf, 10, 16)
		if err != nil || queues <= 0 {
			return fmt.Errorf("Invalid %s configuration: %s parses to %d err %v", TapRXQueuesEnvVar, conf, queues, err)
		}
		TapRXQueues = int(queues)
	}

	if conf := os.Getenv(TapGSOEnvVar); conf != "" {
		gso, err := strconv.ParseBool(conf)
		if err != nil {
			return fmt.Errorf("Invalid %s configuration: %s parses to %v err %v", TapGSOEnvVar, conf, gso, err)
		}
		TapGSOEnabled = gso
	}
	return nil
}
