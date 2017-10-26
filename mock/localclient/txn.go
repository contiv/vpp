package localclient

import (
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/ligato/vpp-agent/clientv1/linux"
)

// TxnTracker tracks all transactions executed or pending in the mock localclient.
type TxnTracker struct {
	// lock allows to use the same mock localclient from multiple go routines.
	lock sync.Mutex
	// AppliedConfig represents the current state of the mock DB.
	AppliedConfig ConfigSnapshot
	// CommittedTxns is a list finalized transaction in the order as they were
	// committed.
	CommittedTxns []*Txn
	// PendingTxns is map of pending (uncommitted) transactions.
	PendingTxns map[*Txn]struct{}
	// onCommit if defined is executed inside the transaction commit.
	onCommit func(txn *Txn) error
}

// ConfigSnapshot represents the current state of a mock DB.
type ConfigSnapshot map[string]proto.Message

// Txn stores all information about a transaction.
// Exactly one of the fields is non-nil.
type Txn struct {
	// DataResyncTxn is non-nil for RESYNC transaction.
	DataResyncTxn *MockDataResyncDSL
	// DataChangeTxn is non-nil for Data Change transaction.
	DataChangeTxn *MockDataChangeDSL
}

// TxnOp stores all information about a transaction operation.
type TxnOp struct {
	// Key under which the value is stored or from which the value was removed.
	Key string
	// Value stored under the key or nil if it was deleted.
	Value proto.Message /* nil if deleted */
}

// NewTxnTracker is a constructor for TxnTracker.
// It is the entry-point to the mock localclient for both linux and vpp.
func NewTxnTracker(onCommit func(txn *Txn) error) *TxnTracker {
	tracker := &TxnTracker{onCommit: onCommit}
	tracker.Clear()
	return tracker
}

// NewDataChangeTxn is a factory for DataChange transactions.
func (t *TxnTracker) NewDataChangeTxn() linux.DataChangeDSL {
	txn := &Txn{}
	dsl := newMockDataChangeDSL(t, txn)
	txn.DataChangeTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// NewDataResyncTxn is a factory for RESYNC transactions.
func (t *TxnTracker) NewDataResyncTxn() linux.DataResyncDSL {
	txn := &Txn{}
	dsl := newMockDataResyncDSL(t, txn)
	txn.DataResyncTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// Clear clears the TxnTracker state. Already created transactions become invalid.
func (t *TxnTracker) Clear() {
	t.AppliedConfig = make(map[string]proto.Message)
	t.CommittedTxns = []*Txn{}
	t.PendingTxns = make(map[*Txn]struct{})
}

// commit applies a transaction.
func (t *TxnTracker) commit(txn *Txn) error {
	var err error
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.onCommit != nil {
		err = t.onCommit(txn)
	}
	if txn.DataChangeTxn != nil {
		txn.DataChangeTxn.apply()
	} else if txn.DataResyncTxn != nil {
		txn.DataResyncTxn.apply()
	}
	delete(t.PendingTxns, txn)
	t.CommittedTxns = append(t.CommittedTxns, txn)
	return err
}
