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

package config

const (
	// by default traffic is equally distributed between local and remote backends
	defaultServiceLocalEndpointWeight = 1
)

// Config holds the Service configuration.
type Config struct {
	// if enabled, the agent will periodically check for idle NAT sessions and delete inactive ones
	CleanupIdleNATSessions      bool   `json:"cleanupIdleNATSessions"`

	// NAT session timeout (in minutes) for TCP connections, used in case that CleanupIdleNATSessions is turned on
	TCPNATSessionTimeout        uint32 `json:"tcpNATSessionTimeout"`

	// NAT session timeout (in minutes) for non-TCP connections, used in case that CleanupIdleNATSessions is turned on
	OtherNATSessionTimeout      uint32 `json:"otherNATSessionTimeout"`

	// how much locally deployed endpoints are more likely to receive a connection
	ServiceLocalEndpointWeight  uint8  `json:"serviceLocalEndpointWeight"`

	// if true, NAT plugin will drop fragmented packets
	DisableNATVirtualReassembly bool   `json:"disableNATVirtualReassembly"`
}

// DefaultConfig returns configuration for service plugin with default values.
func DefaultConfig() *Config {
	return &Config{
		ServiceLocalEndpointWeight: defaultServiceLocalEndpointWeight,
	}
}
