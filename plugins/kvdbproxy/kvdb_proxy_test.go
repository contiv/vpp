// Copyright (c) 2017 Cisco and/or its affiliates.
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

package kvdbproxy

import (
	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/onsi/gomega"
	"testing"
	"time"
)

func TestWatch(t *testing.T) {
	gomega.RegisterTestingT(t)

	kvdbMock := NewKvdbsyncMock()

	plugin := Plugin{}
	plugin.Deps.Log = logging.ForPlugin("proxy", logrus.NewLogRegistry())
	plugin.Deps.KVDB = kvdbMock

	err := plugin.Init()
	gomega.Expect(err).To(gomega.BeNil())

	ch := make(chan datasync.ChangeEvent, 1)

	plugin.Watch("test", ch, nil, "/abc/prefix")

	// expect message to be received
	plugin.Put("/abc/prefix/something", nil)
	select {
	case change := <-ch:
		gomega.Expect(change.GetKey()).To(gomega.BeEquivalentTo("/abc/prefix/something"))
		gomega.Expect(change.GetChangeType()).To(gomega.BeEquivalentTo(datasync.Put))
	case <-time.After(100 * time.Millisecond):
		t.FailNow()
	}

	// expect the message to be filtered out
	plugin.AddIgnoreEntry("/abc/prefix/something", datasync.Put)
	plugin.Put("/abc/prefix/something", nil)

	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):

	}

	// expect message to be received
	plugin.Delete("/abc/prefix/something")
	// add dummy ignore entries
	plugin.AddIgnoreEntry("/abc/prefix/dfafdasfadfadf", datasync.Delete)
	plugin.AddIgnoreEntry("/abc/prefix/adfasfgasf", datasync.Put)
	select {
	case change := <-ch:
		gomega.Expect(change.GetKey()).To(gomega.BeEquivalentTo("/abc/prefix/something"))
		gomega.Expect(change.GetChangeType()).To(gomega.BeEquivalentTo(datasync.Delete))
	case <-time.After(100 * time.Millisecond):
		t.FailNow()
	}

	// expect the message to be filtered out
	plugin.AddIgnoreEntry("/abc/prefix/something", datasync.Delete)
	plugin.Delete("/abc/prefix/something")

	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):

	}

	err = plugin.Close()
	gomega.Expect(err).To(gomega.BeNil())

	close(ch)
}
