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

// Shutdown event is triggered when the agent is being closed.
type Shutdown struct {
	result chan error
}

// NewShutdownEvent is constructor for Shutdown event.
func NewShutdownEvent() *Shutdown {
	return &Shutdown{
		result: make(chan error, 1),
	}
}

// GetName returns name of the Shutdown event.
func (ev *Shutdown) GetName() string {
	return "Shutdown"
}

// String describes Shutdown event.
func (ev *Shutdown) String() string {
	return ev.GetName()
}

// Method is Update.
func (ev *Shutdown) Method() EventMethodType {
	return Update
}

// TransactionType is BestEffort.
func (ev *Shutdown) TransactionType() UpdateTransactionType {
	return BestEffort
}

// Direction is forward.
func (ev *Shutdown) Direction() UpdateDirectionType {
	return Forward
}

// IsBlocking returns true.
func (ev *Shutdown) IsBlocking() bool {
	return true
}

// Done propagates result to the event producer.
func (ev *Shutdown) Done(err error) {
	ev.result <- err
}

// Waits waits for the result of the shutdown event.
func (ev *Shutdown) Wait() error {
	return <-ev.result
}
