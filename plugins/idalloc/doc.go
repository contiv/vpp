// Copyright (c) 2019 Cisco and/or its affiliates.
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

// Package idalloc is responsible for allocation of numeric identifiers in distributed manner,
// where each node in the cluster needs to be able to allocate an unique ID from the given pool
// for a given purpose identified by a string label, but once allocated, other nodes can not change
// / allocate a different ID for given purpose (label).
package idalloc
