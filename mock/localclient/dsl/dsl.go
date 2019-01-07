//Package dsl is base package for mocks of DSL transaction creators. The main purpose of these mock is to simulate DSL
// usage and to record called steps (transaction operations).
package dsl

import (
	"github.com/gogo/protobuf/proto"
)

// CommonMockDSL holds common data for all mocked DSLs
type CommonMockDSL struct {
	// A map of changes executed in the transaction.
	// nil value represents delete
	Values map[string]proto.Message

	// CommitFunc is function called from inside DSL to trigger commit processing(applying TxnOp-s retrieved by DSL,...)
	// in TxnTracker
	CommitFunc CommitFunc
}

// NewCommonMockDSL is a constructor for CommonMockDSL
func NewCommonMockDSL(commitFunc CommitFunc) CommonMockDSL {
	return CommonMockDSL{
		CommitFunc: commitFunc,
		Values:     make(map[string]proto.Message),
	}
}

// CommitFunc is function called from inside DSL to trigger commit processing(applying TxnOp-s retrieved by DSL,...)
// in TxnTracker
type CommitFunc = func(values map[string]proto.Message) error

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
