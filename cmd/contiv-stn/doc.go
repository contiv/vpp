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

// Contiv-stn is a Daemon which acts as a GRPC server, serving "Steal the NIC"
// requests - requests to unbind an interface from the kernel driver.
//
// Before processing such a request, it remembers the old config, so that
// it is able to revert to the previous state later. Once the interface is
// unconfigured, STN Daemon starts watching contiv-vpp health check probe
// (after the initial timeout). In case that the contiv-vpp is not responding,
// the STN Daemon reverts the interface back to the original state:
// unbinds the interface form the current driver and binds it to the original
// kernel driver, configures back the original IPs and routes that were pointing
// to that interface.
//
// STN Daemon is designed to run in its own Docker container, running under plain
// Docker, so that it is independent of the k8s cluster infrastructure.
package main
