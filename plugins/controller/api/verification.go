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

package api

// VerificationResync is used to verify the preservation of state consistency
// of Contiv plugins after any event.
type VerificationResync struct {
}

// GetName returns name of the VerificationResync event.
func (ev *VerificationResync) GetName() string {
	return "Verification Resync"
}

// String describes VerificationResync event.
func (ev *VerificationResync) String() string {
	return ev.GetName()
}

// Method is UpstreamResync.
func (ev *VerificationResync) Method() EventMethodType {
	return UpstreamResync
}

// IsBlocking returns false.
func (ev *VerificationResync) IsBlocking() bool {
	return false
}

// Done is NOOP.
func (ev *VerificationResync) Done(error) {
	return
}
