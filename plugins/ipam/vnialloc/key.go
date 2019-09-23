// Copyright (c) 2018 Cisco and/or its affiliates.
// Other Contributors: 1. Adel Bouridah Centre Universitaire Abdelhafid Boussouf Mila - Algerie a.bouridah@centre-univ-mila.dz
// 2. Nadjib Aitsaadi Universite Paris Est Creteil, Nadjib.Aitsaadi@u-pec.fr
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

package vnialloc

import (
	"strconv"
)

// VNIAllocationKeyword defines the keyword identifying VNI allocations.
const VNIAllocationKeyword = "vni/allocation"

// VNIAllocationKeyPrefix return prefix where all VNI allocations are persisted.
func VNIAllocationKeyPrefix() string {
	return VNIAllocationKeyword + "/"
}

// VNIAllocationKey returns the key under which VNI allocation data should be stored in the data-store.
func VNIAllocationKey(vni uint32) string {
	return VNIAllocationKeyPrefix() + strconv.Itoa(int(vni))
}

// VxlanVNIKeyword defines the keyword identifying VNI allocation data of VXLANs.
const VxlanVNIKeyword = "vni/vxlan"

// VxlanVNIKeyPrefix return prefix where all VNI allocation data of VXLANs are persisted.
func VxlanVNIKeyPrefix() string {
	return VxlanVNIKeyword + "/"
}

// VxlanVNIKey returns the key under which VNI allocation data of a VXLAN should be stored in the data-store.
func VxlanVNIKey(vxlanName string) string {
	return VxlanVNIKeyPrefix() + vxlanName
}
