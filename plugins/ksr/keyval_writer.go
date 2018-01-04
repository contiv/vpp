package ksr

import (
	"errors"

	"github.com/golang/protobuf/proto"

	"github.com/ligato/cn-infra/datasync"
)

// Error message if not data is found for a given key
const (
	noDataForKey = "No data assigned to key "
)

// KeyProtoValWriter allows reflectors to push their data changes to a data store.
// This interface extends the same name interface from cn-infra/datasync with
// the Delete() operation.
type KeyProtoValWriter interface {
	// Put <data> to ETCD or to any other key-value based data source.
	Put(key string, data proto.Message, opts ...datasync.PutOption) error

	// Delete data under the <key> in ETCD or in any other key-value based data
	// source.
	Delete(key string, opts ...datasync.DelOption) (existed bool, err error)
}

// mockKeyProtoValWriter is a mock implementation of KeyProtoValWriter used in unit tests.
type mockKeyProtoValWriter struct {
	ds map[string]proto.Message
}

// newMockKeyProtoValWriter initializes a new instance of mockKeyProtoValWriter.
func newMockKeyProtoValWriter() *mockKeyProtoValWriter {
	mock := &mockKeyProtoValWriter{}
	mock.ds = make(map[string]proto.Message)
	return mock
}

// Put puts data into an in-memory map simulating a key-value datastore.
func (mock *mockKeyProtoValWriter) Put(key string, data proto.Message, opts ...datasync.PutOption) error {
	mock.ds[key] = data
	return nil
}

// Delete removes data from an in-memory map simulating a key-value datastore.
func (mock *mockKeyProtoValWriter) Delete(key string, opts ...datasync.DelOption) (existed bool, err error) {
	_, existed = mock.ds[key]
	if !existed {
		return false, nil
	}
	delete(mock.ds, key)
	return true, nil
}

// GetValue is a helper for unit tests to get value stored under a given key.
func (mock *mockKeyProtoValWriter) GetValue(key string, out proto.Message) (err error) {
	data, exists := mock.ds[key]
	if !exists {
		return errors.New(noDataForKey + key)
	}
	proto.Merge(out, data)
	return nil
}

// ClearDs is a helper which allows to clear the in-memory map simulating
// a key-value datastore.
func (mock *mockKeyProtoValWriter) ClearDs() {
	for key := range mock.ds {
		delete(mock.ds, key)
	}
}
