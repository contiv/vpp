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

import (
	"context"

	"github.com/gogo/protobuf/proto"
)

// Transaction defines operations needed to build and commit a transaction.
type Transaction interface {
	UpdateOperations

	// Commit applies the requested transaction changes.
	Commit(ctx context.Context) error
}

// ResyncOperations lists operations needed to build transaction for Resync-type events.
type ResyncOperations interface {
	// Put add request to the transaction to add or modify a value.
	// <value> cannot be nil.
	Put(key string, value proto.Message)

	// Get is used to obtain value already prepared to be applied by this transaction.
	// Until the transaction is committed, provided values can still be changed.
	// Returns nil if the value is set to be deleted, or has not been set at all.
	Get(key string) proto.Message
}

// UpdateOperations lists operations needed to build transaction for Update-type events.
type UpdateOperations interface {
	ResyncOperations

	// Delete adds request to the transaction to delete an existing value.
	Delete(key string)
}

// PutAll is a helper function to prepare Put for multiple key-value pairs into
// a single transaction.
func PutAll(txn Transaction, values KeyValuePairs) {
	for key, value := range values {
		txn.Put(key, value)
	}
}

// DeleteAll is a helper function to prepare Delete for multiple key-value pairs into
// a single transaction.
func DeleteAll(txn Transaction, values KeyValuePairs) {
	for key := range values {
		txn.Delete(key)
	}
}
