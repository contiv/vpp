//Package dsl is base package for mocks of DSL transaction creators. The main purpose of these mock is to simulate DSL
// usage and to record called steps (transaction operations).
package dsl

import (
	"github.com/gogo/protobuf/proto"
)

//CommonMockDSL holds common data for all mocked DSLs
type CommonMockDSL struct {
	// List of transaction operations in the order as they were called.
	Ops []TxnOp

	// CommitFunc is function called from inside DSL to trigger commit processing(applying TxnOp-s retrieved by DSL,...)
	// in TxnTracker
	CommitFunc CommitFunc
}

// TxnOp stores all information about a transaction operation.
type TxnOp struct {
	// Key under which the value is stored or from which the value was removed.
	Key string
	// Value stored under the key or nil if it was deleted.
	Value proto.Message /* nil if deleted */
}

// CommitFunc is function called from inside DSL to trigger commit processing(applying TxnOp-s retrieved by DSL,...)
// in TxnTracker
type CommitFunc = func(Ops []TxnOp) error

// Reply interface allows to wait for a reply to previously called Send() and
// extract the result from it (success/error).
type Reply struct {
	Err error
}

// ReceiveReply waits for a reply to previously called Send() and returns
// the result (error or nil).
func (dsl Reply) ReceiveReply() error {
	return dsl.Err
}
