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
//
// Contiv-cni is a CNI plugin (binary) that forwards the CNI requests to the
// gRPC server specified in the CNI config file. The response from gRPC server
// is then processed back into the standard output of the CNI plugin.
// This plugin implements the CNI specification version 0.3.1
// (https://github.com/containernetworking/cni/blob/spec-v0.3.1/SPEC.md).
package main
