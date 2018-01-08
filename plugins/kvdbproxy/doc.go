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

// Package kvdbproxy implements proxy for a kvdbsync with ability to skip selected change events.
//
// The primary use case is:
//   - a plugin watches configuration in key-value datastore and processes the changes in a "standard" way
//   - a part of the configuration is processed "alternatively" and it
// 	   is persisted into key-value datastore afterwards
//   - the change events caused by persisting need to be ignored since the change is already applied
//
// The limitations:
// 	 - it is not possible to define multiple ignored events for the key.
package kvdbproxy
