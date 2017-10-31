// Copyright (c) 2017 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package contiv

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"sync"

	"github.com/ligato/cn-infra/logging"
)

// IPAM represents the basic Contiv IPAM module.
// TODO: this is just an initial implementation, requires a lot of work.
type IPAM struct {
	logging.Logger
	sync.RWMutex

	podSubnetCIDR       string // subnet from which individual pod networks are allocated
	podNetworkSubnetID  uint8  // unique ID of the pod subnet on this host, used to calculate podNetworkIPPrefix
	podNetworkIPPrefix  string // prefix with pod network IP, ID of the pod can be appended to this to get the real pod IP
	podNetworkPrefixLen uint32 // prefix length of pod network used on this host
	podSeqID            uint32 // pod sequence number used to allocate an unique pod IP address to each POD
}

// newIPAM returns new IPAM module to be used on the host.
func newIPAM(logger logging.Logger, podSubnetCIDR string, podNetworkPrefixLen uint32, agentLabel string) *IPAM {
	ipam := &IPAM{
		Logger:        logger,
		podSubnetCIDR: podSubnetCIDR,
		podSeqID:      1, // .1 wil be the gateway address
	}

	// calculate POD subnetID ID based on agentLabel
	// TODO: implement proper allocation logic based on ETCD
	h := sha1.New()
	h.Write([]byte(agentLabel))
	sum := h.Sum(nil)
	ipam.podNetworkSubnetID = uint8(sum[0])
	logger.Infof("Will use %d as the pod network subnet ID.", ipam.podNetworkSubnetID)

	// TODO: process podSubnetCIDR properly, for now this assumes pod subnet to be /16 and pod network /24
	cidrArr := strings.Split(podSubnetCIDR, ".")

	ipam.podNetworkIPPrefix = fmt.Sprintf("%s.%s.%d", cidrArr[0], cidrArr[1], ipam.podNetworkSubnetID)
	ipam.podNetworkPrefixLen = podNetworkPrefixLen

	logger.Infof("POD network for this node will be %s.X/%d", ipam.podNetworkIPPrefix, ipam.podNetworkPrefixLen)

	return ipam
}

// getPodSubnetCIDR returns pod subnet CIDR ("network_address/prefix_length").
func (i *IPAM) getPodSubnetCIDR() string {
	i.RLock()
	defer i.RUnlock()
	return i.podSubnetCIDR
}

// getPodNetworkCIDR returns pod network CIDR ("network_address/prefix_length").
func (i *IPAM) getPodNetworkCIDR() string {
	i.RLock()
	defer i.RUnlock()
	return fmt.Sprintf("%s.%d/%d", i.podNetworkIPPrefix, 0, i.podNetworkPrefixLen)
}

// getPodGatewayIP returns gateway IP address for the pod network.
func (i *IPAM) getPodGatewayIP() string {
	i.RLock()
	defer i.RUnlock()
	return fmt.Sprintf("%s.%d", i.podNetworkIPPrefix, 1)
}

// getPodNetworkSubnetID returns unique ID of the pod subnet on this host, used to calculate the pod network CIDR.
func (i *IPAM) getPodNetworkSubnetID() uint8 {
	i.RLock()
	defer i.RUnlock()
	return i.podNetworkSubnetID
}

// getNextPodIP returns next available pod IP address.
func (i *IPAM) getNextPodIP() string {
	i.Lock()
	defer i.Unlock()

	// TODO: implement proper pool logic instead of sequence numbers

	// assign next available IP
	i.podSeqID++
	ip := fmt.Sprintf("%s.%d", i.podNetworkIPPrefix, i.podSeqID)

	i.Logger.Infof("Assigned new pod IP %s", ip)

	return ip
}

// releasePodIP releases the pod IP address, so that it can be reused by the next pods.
func (i *IPAM) releasePodIP(ip string) error {
	// TODO: implement
	return fmt.Errorf("not yet implemented")
}
