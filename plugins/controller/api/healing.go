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

package api

import "fmt"

// HealingResyncType is either Periodic or AfterError.
type HealingResyncType int

const (
	// Periodic healing resync, when enabled in the configuration, is run periodically
	// to trigger the Downstream resync (sync between vpp-agent and VPP/Linux).
	Periodic HealingResyncType = iota

	// AfterError healing resync is triggered after an event processing ended with error.
	AfterError
)

// HealingResync is supposed to "heal" the contiv-vswitch. It is run either
// after an error occurred or periodically.
type HealingResync struct {
	Type  HealingResyncType
	Error error // non-nil if the resync is of type AfterError
}

// GetName returns name of the HealingResync event.
func (ev *HealingResync) GetName() string {
	return "Healing Resync"
}

// String describes HealingResync event.
func (ev *HealingResync) String() string {
	str := ev.GetName()
	if ev.Type == AfterError {
		str += fmt.Sprintf(" (After error: %v)", ev.Error)
	} else {
		str += " (Periodic)"
	}
	return str
}

// Method is Resync.
func (ev *HealingResync) Method() EventMethodType {
	return Resync
}

// IsBlocking returns false.
func (ev *HealingResync) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *HealingResync) Done(error) {
	return
}
