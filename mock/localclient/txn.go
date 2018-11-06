//Package localclient contains mocks for transactions created by DSL structures in localclient packages.
package localclient

import (
	"sync"

	"github.com/contiv/vpp/mock/localclient/dsl"
	mocklinux "github.com/contiv/vpp/mock/localclient/dsl/linux"
	mockvpp "github.com/contiv/vpp/mock/localclient/dsl/vpp"
	"github.com/gogo/protobuf/proto"
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/datasync/syncbase"
	"github.com/ligato/vpp-agent/clientv2/linux"
	"github.com/ligato/vpp-agent/clientv2/vpp"
)

// TxnTracker tracks all transactions executed or pending in the mock localclient.
type TxnTracker struct {
	// lock allows to use the same mock localclient from multiple go routines.
	lock sync.Mutex
	// LatestRevisions maintains the map of keys & values with revision.
	LatestRevisions *syncbase.PrevRevisions
	// CommittedTxns is a list finalized transaction in the order as they were
	// committed.
	CommittedTxns []*Txn
	// PendingTxns is map of pending (uncommitted) transactions.
	PendingTxns map[*Txn]struct{}
	// onCommit if defined is executed inside the transaction commit.
	onCommit func(txn *Txn, latestRevs *syncbase.PrevRevisions) error
}

// ConfigSnapshot represents the current state of a mock DB.
type ConfigSnapshot map[string]proto.Message

// Txn stores all information about a transaction.
// Exactly one of the fields is non-nil.
type Txn struct {
	// LinuxDataResyncTxn is non-nil for Linux Plugin's RESYNC transaction.
	LinuxDataResyncTxn *mocklinux.MockDataResyncDSL
	// LinuxDataChangeTxn is non-nil for Linux Plugin's Data Change transaction.
	LinuxDataChangeTxn *mocklinux.MockDataChangeDSL
	// VPPDataResyncTxn is non-nil for VPP Plugins's Data Resync transaction.
	VPPDataResyncTxn *mockvpp.MockDataResyncDSL
	// VPPDataChangeTxn is non-nil for VPP Plugin's Data Change transaction.
	VPPDataChangeTxn *mockvpp.MockDataChangeDSL
}

// NewTxnTracker is a constructor for TxnTracker.
// It is the entry-point to the mock localclient for both linux and vpp.
func NewTxnTracker(onCommit func(txn *Txn, latestRevs *syncbase.PrevRevisions) error) *TxnTracker {
	tracker := &TxnTracker{onCommit: onCommit}
	tracker.Clear()
	return tracker
}

// NewLinuxDataChangeTxn is a factory for DataChange transactions.
func (t *TxnTracker) NewLinuxDataChangeTxn() linuxclient.DataChangeDSL {
	txn := &Txn{}
	dsl := mocklinux.NewMockDataChangeDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataChangeTxnOps, Ops) })
	txn.LinuxDataChangeTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// NewVPPDataChangeTxn is a factory for VPP Plugins's DataChange transactions.
func (t *TxnTracker) NewVPPDataChangeTxn() vppclient.DataChangeDSL {
	txn := &Txn{}
	dsl := mockvpp.NewMockDataChangeDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataChangeTxnOps, Ops) })
	txn.VPPDataChangeTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// applyDataChangeTxnOps reflects the effect of data change transaction operations into the mock DB.
func (t *TxnTracker) applyDataChangeTxnOps(ops []dsl.TxnOp) {
	for _, op := range ops {
		if op.Value != nil {
			change := syncbase.NewChange(op.Key, op.Value, 0, datasync.Put)
			t.LatestRevisions.Put(op.Key, change)
		} else {
			t.LatestRevisions.Del(op.Key)
		}
	}
}

// NewLinuxDataResyncTxn is a factory for Linux Plugins's RESYNC transactions.
func (t *TxnTracker) NewLinuxDataResyncTxn() linuxclient.DataResyncDSL {
	txn := &Txn{}
	dsl := mocklinux.NewMockDataResyncDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataResyncTxnOps, Ops) })
	txn.LinuxDataResyncTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// NewVPPDataResyncTxn is a factory for VPP plugins's RESYNC transactions.
func (t *TxnTracker) NewVPPDataResyncTxn() vppclient.DataResyncDSL {
	txn := &Txn{}
	dsl := mockvpp.NewMockDataResyncDSL(func(Ops []dsl.TxnOp) error { return t.commit(txn, t.applyDataResyncTxnOps, Ops) })
	txn.VPPDataResyncTxn = dsl
	t.PendingTxns[txn] = struct{}{}
	return dsl
}

// applyDataResyncTxnOps reflects the effect of data resync transaction operations into the mock DB.
func (t *TxnTracker) applyDataResyncTxnOps(ops []dsl.TxnOp) {
	for _, op := range ops {
		change := syncbase.NewChange(op.Key, op.Value, 0, datasync.Put)
		t.LatestRevisions.PutWithRevision(op.Key, change)
	}
}

// Clear clears the TxnTracker state. Already created transactions become invalid.
func (t *TxnTracker) Clear() {
	t.LatestRevisions = syncbase.NewLatestRev()
	t.CommittedTxns = []*Txn{}
	t.PendingTxns = make(map[*Txn]struct{})
}

// commit applies a transaction (and transaction operations to current state of mock DB)
func (t *TxnTracker) commit(txn *Txn, applyTxnOpsFunc func([]dsl.TxnOp), ops []dsl.TxnOp) error {
	var err error
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.onCommit != nil {
		err = t.onCommit(txn, t.LatestRevisions)
	}
	applyTxnOpsFunc(ops)
	delete(t.PendingTxns, txn)
	t.CommittedTxns = append(t.CommittedTxns, txn)
	return err
}
