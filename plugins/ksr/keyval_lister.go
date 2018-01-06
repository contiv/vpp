// Copyright (c) 2018 Cisco and/or its affiliates.
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

package ksr

import "github.com/ligato/cn-infra/db/keyval"

// KeyProtoValWriter allows a reflector to list values that the reflector
// previously stored in in ETCD.
type KeyProtoValLister interface {
	// List values stored in etcd under the given prefix.
	ListValues(prefix string) (keyval.ProtoKeyValIterator, error)
}

