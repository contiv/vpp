package controller

import (
	"context"
	"fmt"
	"sort"

	"github.com/gogo/protobuf/proto"

	scheduler_api "github.com/ligato/vpp-agent/plugins/kvscheduler/api"

	controller "github.com/contiv/vpp/plugins/controller/api"
)

// MockControllerTxn is a mock implementation of the Transaction interface from Controller.
type MockControllerTxn struct {
	Values     controller.KeyValuePairs
	commitFunc CommitFunc
}

// CommitFunc is function called from the mock to trigger transaction processing
// in TxnTracker.
type CommitFunc = func(values map[string]proto.Message) error

// NewMockControllerTxn is a constructor for mock Controller Txn.
func NewMockControllerTxn(commitFunc CommitFunc) *MockControllerTxn {
	return &MockControllerTxn{
		Values:     make(controller.KeyValuePairs),
		commitFunc: commitFunc,
	}
}

// Commit applies the requested transaction changes.
func (m *MockControllerTxn) Commit(ctx context.Context) error {
	isResync := scheduler_api.IsFullResync(ctx)
	description, withDescription := scheduler_api.IsWithDescription(ctx)
	if withDescription {
		description = fmt.Sprintf(" (%s)", description)
	}
	if isResync {
		fmt.Printf("RESYNC transaction%s:\n", description)
	} else {
		fmt.Printf("UPDATE transaction%s:\n", description)
	}

	// print key-value pairs sorted by keys
	var sortedKeys []string
	for key := range m.Values {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		value := m.Values[key]
		fmt.Printf("    - key: %s\n", key)
		valueStr := "<nil>"
		if value != nil {
			valueStr = value.String()
		}
		fmt.Printf("      value: %s\n", valueStr)
	}

	return m.commitFunc(m.Values)
}

// Put add request to the transaction to add or modify a value.
// <value> cannot be nil.
func (m *MockControllerTxn) Put(key string, value proto.Message) {
	if value == nil {
		panic(fmt.Sprintf("Put nil value for key '%s'", key))
	}
	m.Values[key] = value
}

// Delete adds request to the transaction to delete an existing value.
func (m *MockControllerTxn) Delete(key string) {
	m.Values[key] = nil
}

// Get is used to obtain value already prepared to be applied by this transaction.
// Until the transaction is committed, provided values can still be changed.
func (m *MockControllerTxn) Get(key string) proto.Message {
	value, _ := m.Values[key]
	return value
}
