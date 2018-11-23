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

// EventLoop defines method for accessing the main event loop.
type EventLoop interface {
	// PushEvent adds the given event into the queue for processing.
	PushEvent(event Event) error
}

// Event represents something that has happened and may cause some reaction.
type Event interface {
	// GetName should return a string identifier, unique among the event types,
	// but also somewhat descriptive for humans.
	GetName() string

	// String should return a description of the event.
	String() string

	// Method tells whether the event can be reacted to by an incremental change
	// (Update) or if a full re-synchronization is needed (Resync, i.e. complex
	// change).
	Method() EventMethodType

	// IsBlocking should return true if any producer of this event ever waits
	// for the event result (sent using the method Done()).
	IsBlocking() bool

	// Done is used to mark the event as processed.
	// A specific Event implementation may use this method for example to deliver
	// the return value back to the send of the event.
	Done(error)
}

// UpdateEvent can be reacted to by an incremental change, as opposed to the full
// re-synchronization.
type UpdateEvent interface {
	// TransactionType defines how to treat already executed changes of a failed
	// event processing - whether to keep them (and be as close to the desired
	// state as it was possible) or to revert them (a proper transaction).
	TransactionType() UpdateTransactionType

	// Direction determines the direction in which the event should flow through
	// the event handlers.
	Direction() UpdateDirectionType
}

// EventHandler declares methods that event handler must implement.
type EventHandler interface {
	// String identifies the handler for the Controller and in the logs.
	// Note: Plugins already implement Stringer.
	String() string

	// HandlesEvent is used by Controller to check if the event is being handled
	// by this handler.
	HandlesEvent(event Event) bool

	// Resync is called by Controller to handle event that requires full
	// re-synchronization.
	// For startup resync, resyncCount is 1. Higher counter values identify
	// run-time resync.
	Resync(event Event, txn ResyncOperations, kubeStateData KubeStateData, resyncCount int) error

	// Update is called by Controller to handle event that can be reacted to by
	// an incremental change.
	// <changeDescription> should be human-readable description of changes that
	// have to be performed (via txn or internally) - can be empty.
	Update(event Event, txn UpdateOperations) (changeDescription string, err error)

	// Revert is called to revert already executed internal changes (in the plugin
	// itself, not in VPP/Linux network stack) for a RevertOnFailure event that
	// has failed in the processing.
	Revert(event Event) error
}

// EventMethodType is either Resync or Update.
type EventMethodType int

const (
	// Resync event requires to be reacted to by a full re-synchronization.
	Resync EventMethodType = iota

	// Update event can be reacted to by an incremental change.
	Update
)

// UpdateDirectionType is either Forward or Reverse.
type UpdateDirectionType int

const (
	// Forward event is processed by handlers in the exact same order as passed
	// to the Controller - ensuring for every handler that its dependencies
	// have already reacted to the event.
	Forward UpdateDirectionType = iota

	// Reverse event is processed by handlers in the backward order, ensuring
	// for every handler that its dependencies are still in the pre-event state.
	Reverse
)

// UpdateTransactionType is either BestEffort or RevertOnFailure.
type UpdateTransactionType int

const (
	// BestEffort transaction continues even if non-fatal, non-abort error
	// is returned (to get as close to the desired state as it is possible).
	BestEffort UpdateTransactionType = iota

	// RevertOnFailure tells the Controller to stop event processing when any error
	// is returned and to revert already executed changes.
	RevertOnFailure
)
