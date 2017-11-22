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

package utils

import (
	"bytes"
	"net"
	"strings"

	namespacemodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"
)

// RemoveDuplicates removes duplicates entries for a slice of strings
func RemoveDuplicates(el []string) []string {
	found := map[string]bool{}

	// Create a map of all unique elements.
	for v := range el {
		found[el[v]] = true
	}

	// Place all keys from the map into a slice.
	result := []string{}
	for key := range found {
		result = append(result, key)
	}
	return result
}

// Intersect returns the common elements of two slices
func Intersect(a []string, b []string) []string {
	set := make([]string, 0)
	hash := make(map[string]bool)

	for _, el := range a {
		hash[el] = true
	}

	for _, el := range b {
		if _, found := hash[el]; found {
			set = append(set, el)
		}
	}
	return set
}

// Difference returns the difference of two slices
func Difference(a []string, b []string) []string {
	set := make([]string, 0)
	hash := make(map[string]bool)
	// Populate the map
	for _, el := range a {
		hash[el] = true
	}
	//Append to slice for every element that exists on the hash
	for _, el := range b {
		if _, found := hash[el]; !found {
			set = append(set, el)
		}
	}
	return set
}

// UnstringPodID converts string podIDs to podmodelIDs
func UnstringPodID(pods []string) []podmodel.ID {
	podIDs := []podmodel.ID{}
	for _, pod := range pods {
		parts := strings.Split(pod, "/")
		podID := podmodel.ID{
			Name:      parts[1],
			Namespace: parts[0],
		}
		podIDs = append(podIDs, podID)
	}
	return podIDs
}

// StringPodID converts  podmodelIDs to string podIDs
func StringPodID(pods []podmodel.ID) []string {
	podIDs := []string{}
	for _, pod := range pods {
		podID := pod.Namespace + "/" + pod.Name
		podIDs = append(podIDs, podID)
	}
	return podIDs
}

// UnstringPolicyID converts string policyIDs to policymodelIDs
func UnstringPolicyID(policies []string) []policymodel.ID {
	policyIDs := []policymodel.ID{}
	for _, policy := range policies {
		parts := strings.Split(policy, "/")
		policyID := policymodel.ID{
			Name:      parts[1],
			Namespace: parts[0],
		}
		policyIDs = append(policyIDs, policyID)
	}
	return policyIDs
}

// StringPolicyID converts policymodelIDs to string policyIDs
func StringPolicyID(policies []policymodel.ID) []string {
	policyIDs := []string{}
	for _, policy := range policies {
		policyID := policy.Namespace + "/" + policy.Name
		policyIDs = append(policyIDs, policyID)
	}
	return policyIDs
}

// UnstringNamespaceID converts string namespaceIDs to namespacemodelIDs
func UnstringNamespaceID(namespaces []string) []namespacemodel.ID {
	namespaceIDs := []namespacemodel.ID{}
	for _, namespace := range namespaces {
		namespaceID := namespacemodel.ID(namespace)
		namespaceIDs = append(namespaceIDs, namespaceID)
	}
	return namespaceIDs
}

// ConstructLabels returns a key-value pair as a label given an expression
func ConstructLabels(key string, values []string) []*policymodel.Policy_Label {
	policyLabel := []*policymodel.Policy_Label{}
	for _, label := range values {
		policyLabel = append(policyLabel,
			&policymodel.Policy_Label{
				Key:   key,
				Value: label,
			})
	}
	return policyLabel
}

// CompareInts is a comparison function for two integers.
func CompareInts(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// CompareIPNets returns an integer comparing two IP network addresses
// lexicographically.
func CompareIPNets(a, b *net.IPNet) int {
	ipOrder := bytes.Compare(a.IP, b.IP)
	if ipOrder == 0 {
		return bytes.Compare(a.Mask, b.Mask)
	}
	return ipOrder
}

// CompareIPNetsBytes returns an integer comparing two IP network addresses
// represented as raw bytes lexicographically.
func CompareIPNetsBytes(aPrefixLen uint8, aIP [16]byte, bPrefixLen uint8, bIP [16]byte) int {
	prefixOrder := CompareInts(int(aPrefixLen), int(bPrefixLen))
	if prefixOrder != 0 {
		return prefixOrder
	}
	return bytes.Compare(aIP[:], bIP[:])
}

// GetOneHostSubnet returns the IP subnet that contains only the given host
// (i.e. /32 for IPv4, /128 for IPv6).
func GetOneHostSubnet(hostAddr string) *net.IPNet {
	ip := net.ParseIP(hostAddr)
	if ip == nil {
		return nil
	}
	ipNet := &net.IPNet{IP: ip}
	if ip.To4() != nil {
		ipNet.Mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)
	} else {
		ipNet.Mask = net.CIDRMask(net.IPv6len*8, net.IPv6len*8)
	}
	return ipNet
}
