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

package cache

import (
	"net"
	"testing"

	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/logging/logroot"
	"github.com/onsi/gomega"
)

func ipNetwork(addr string) *net.IPNet {
	if addr == "" {
		return &net.IPNet{}
	}
	_, network, error := net.ParseCIDR(addr)
	gomega.Expect(error).To(gomega.BeNil())
	return network
}

func TestSomething(t *testing.T) {
	gomega.RegisterTestingT(t)
	logger := logroot.StandardLogger()
	logger.SetLevel(logging.DebugLevel)
	logger.Debug("TestSomething")

	// Create an instance of SessionRuleCache
	ruleCache := &SessionRuleCache{
		Deps: Deps{
			Log: logger,
		},
	}
	ruleCache.Init(func() SessionRuleList { return NewSessionRuleList(0) })

	gomega.Expect(ruleCache.AllNamespaces()).To(gomega.BeEmpty())

}
