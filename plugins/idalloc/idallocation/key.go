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

package idallocation

// Keyword defines the keyword identifying ID allocation pools.
const Keyword = "idalloc"

// KeyPrefix return prefix where all ID allocation pools are persisted.
func KeyPrefix() string {
	return Keyword + "/"
}

// Key returns the key under which ID allocation pool data should be stored in the data-store.
func Key(poolName string) string {
	return KeyPrefix() + poolName
}
