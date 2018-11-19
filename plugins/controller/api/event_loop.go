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

// EventLoop
type EventLoop interface {
	// PushEvent
	PushEvent(event Event)
}

// Event
type Event interface {
	GetName() string

	// String
	String() string

	// Method
	Method() EventMethodType
}

// UpdateEvent
type UpdateEvent interface {
	// TransactionType
	TransactionType() UpdateTransactionType

	// Direction
	Direction() UpdateDirectionType
}

type EventHandler interface {
	String() string

	HandlesEvent(event Event) bool

	Resync(event Event, txn ResyncOperations, kubeStateData KubeStateData, resyncCount int) error

	Update(event Event, txn UpdateOperations) (changeDescription string, err error)

	Revert(event Event) error
}

// EventMethodType
type EventMethodType int

const (
	// Resync
	Resync EventMethodType = iota

	// Update
	Update
)

// UpdateDirectionType
type UpdateDirectionType int

const (
	// Forward
	Forward UpdateDirectionType = iota

	// Reverse
	Reverse
)

// UpdateTransactionType
type UpdateTransactionType int

const (
	// BestEffort
	BestEffort UpdateTransactionType = iota

	// RevertOnFailure
	RevertOnFailure
)
