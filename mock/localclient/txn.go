//Package localclient contains mocks for transactions created by DSL structures in localclient packages.
package localclient

import (
	"sync"

	"github.com/contiv/vpp/mock/localclient/dsl"
	mockdefaultplugins "github.com/contiv/vpp/mock/localclient/dsl/defaultplugins"
	"github.com/contiv/vpp/mock/localclient/dsl/linuxplugin"
	"github.com/golang/protobuf/proto"
	"github.com/ligato/vpp-agent/clientv1/defaultplugins"
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
	// LinuxDataResyncTxn is non-nil for Linux Plugin's RESYNC transaction.
	LinuxDataResyncTxn *linuxplugin.MockDataResyncDSL
	// LinuxDataChangeTxn is non-nil for Linux Plugin's Data Change transaction.
	LinuxDataChangeTxn *linuxplugin.MockDataChangeDSL
	// DefaultPluginsDataResyncTxn is non-nil for Default Plugins's Data Resync transaction.
	DefaultPluginsDataResyncTxn *mockdefaultplugins.MockDataResyncDSL
	// DefaultPluginsDataChangeTxn is non-nil for Default Plugin's Data Change transaction.
	DefaultPluginsDataChangeTxn *mockdefaultplugins.MockDataChangeDSL
}

// NewTxnTracker is a constructor for TxnTracker.
// It is the entry-point to the mock localclient for both linux and vpp.
func NewTxnTracker(onCommit func(txn *Txn) error) *TxnTracker {
	tracker := &TxnTracker{onCommit: onCommit}
	tracker.Clear()
	return tracker
}

// NewLinuxDataChangeTxn is a factory for DataChange transactions.
func (t *TxnTracker) NewLinuxDataChangeTxn() linux.DataChangeDSL {
	txn := &Txn{}
	dsl := linuxplugin.NewMockDataChangeDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataChangeTxnOps, Ops) })
	txn.LinuxDataChangeTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// NewDefaultPluginsDataChangeTxn is a factory for Default Plugins's DataChange transactions.
func (t *TxnTracker) NewDefaultPluginsDataChangeTxn() defaultplugins.DataChangeDSL {
	txn := &Txn{}
	dsl := mockdefaultplugins.NewMockDataChangeDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataChangeTxnOps, Ops) })
	txn.DefaultPluginsDataChangeTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// applyDataChangeTxnOps reflects the effect of data change transaction operations into the mock DB.
func (t *TxnTracker) applyDataChangeTxnOps(ops []dsl.TxnOp) {
	for _, op := range ops {
		if op.Value != nil {
			t.AppliedConfig[op.Key] = op.Value
		} else {
			_, exists := t.AppliedConfig[op.Key]
			if exists {
				delete(t.AppliedConfig, op.Key)
			}
		}
	}
}

// NewLinuxDataResyncTxn is a factory for Linux Plugins's RESYNC transactions.
func (t *TxnTracker) NewLinuxDataResyncTxn() linux.DataResyncDSL {
	txn := &Txn{}
	dsl := linuxplugin.NewMockDataResyncDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataResyncTxnOps, Ops) })
	txn.LinuxDataResyncTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// NewDefaultPluginsDataResyncTxn is a factory for default plugins's RESYNC transactions.
func (t *TxnTracker) NewDefaultPluginsDataResyncTxn() defaultplugins.DataResyncDSL {
	txn := &Txn{}
	dsl := mockdefaultplugins.NewMockDataResyncDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataResyncTxnOps, Ops) })
	txn.DefaultPluginsDataResyncTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// applyDataResyncTxnOps reflects the effect of data resync transaction operations into the mock DB.
func (t *TxnTracker) applyDataResyncTxnOps(ops []dsl.TxnOp) {
	t.AppliedConfig = make(map[string]proto.Message) /* clear the previous configuration */
	for _, op := range ops {
		t.AppliedConfig[op.Key] = op.Value
	}
}

// Clear clears the TxnTracker state. Already created transactions become invalid.
func (t *TxnTracker) Clear() {
	t.AppliedConfig = make(map[string]proto.Message)
	t.CommittedTxns = []*Txn{}
	t.PendingTxns = make(map[*Txn]struct{})
}

// commit applies a transaction (and transaction operations to current state of mock DB)
func (t *TxnTracker) commit(txn *Txn, applyTxnOpsFunc func([]dsl.TxnOp), ops []dsl.TxnOp) error {
	var err error
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.onCommit != nil {
		err = t.onCommit(txn)
	}
	applyTxnOpsFunc(ops)
	delete(t.PendingTxns, txn)
	t.CommittedTxns = append(t.CommittedTxns, txn)
	return err
}
