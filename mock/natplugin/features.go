/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package natplugin

// NatFeatureType is one of IN, OUT, OUTPUT-IN, OUTPUT-OUT.
type NatFeatureType int

const (
	IN NatFeatureType = iota
	OUT
	OUTPUT_IN
	OUTPUT_OUT
)

func (nft NatFeatureType) String() string {
	switch nft {
	case IN:
		return "IN"
	case OUT:
		return "OUT"
	case OUTPUT_IN:
		return "OUTPUT_IN"
	case OUTPUT_OUT:
		return "OUTPUT_OUT"
	}
	return "INVALID"
}

func (nft NatFeatureType) Opposite() NatFeatureType {
	switch nft {
	case IN:
		return OUTPUT_IN
	case OUT:
		return OUTPUT_OUT
	case OUTPUT_IN:
		return IN
	case OUTPUT_OUT:
		return OUT
	}
	return OUT
}

// NatFeatures is a set of NAT features.
type NatFeatures map[NatFeatureType]struct{}

// NewNatFeatures is a constructor for NatFeatures.
func NewNatFeatures(features ...NatFeatureType) NatFeatures {
	nf := make(NatFeatures)
	for _, feature := range features {
		nf.Add(feature)
	}
	return nf
}

// Add feature into the set.
// Returns false if the feature or its opposite is already there.
func (nf NatFeatures) Add(feature NatFeatureType) bool {
	if !nf.Has(feature) && !nf.Has(feature.Opposite()) {
		nf[feature] = struct{}{}
		return true
	} else {
		return false
	}
}

// Del feature from the set.
func (nf NatFeatures) Del(feature NatFeatureType) {
	if nf.Has(feature) {
		delete(nf, feature)
	}
}

// Copy creates a deep copy of the set.
func (nf NatFeatures) Copy() NatFeatures {
	nfCopy := NewNatFeatures()
	for feature := range nf {
		nfCopy.Add(feature)
	}
	return nfCopy
}

// Has returns true if the given feature is in the set.
func (nf NatFeatures) Has(feature NatFeatureType) bool {
	_, has := nf[feature]
	return has
}

// String converts a set of NAT feature into a human-readable string.
func (nf NatFeatures) String() string {
	str := "{"
	idx := 0
	for feature := range nf {
		str += feature.String()
		if idx < len(nf)-1 {
			str += ", "
		}
		idx++
	}
	str += "}"
	return str
}
