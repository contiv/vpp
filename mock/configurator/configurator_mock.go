/*
 * // Copyright (c) 2017 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package configurator

import (
	"net"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"

	"github.com/contiv/vpp/plugins/policy/configurator"
	"github.com/ligato/cn-infra/logging"
)

type MockPolicyConfigurator struct {
	Log    logging.Logger
	config map[podmodel.ID]ContivPolicies
}

type MockPolicyConfiguratorTxn struct {
	Log          logging.Logger
	configurator *MockPolicyConfigurator
	resync       bool
	config       map[podmodel.ID]ContivPolicies // config to render
}

type ContivPolicies []*ContivPolicy
type MatchType int
type PolicyType int
type ProtocolType int

type Port struct {
	Protocol ProtocolType
	Number   uint16
}

type IPBlock struct {
	Network net.IPNet
	Except  []net.IPNet
}

type ContivPolicy struct {
	ID      policymodel.ID
	Type    PolicyType
	Matches []Match
}

type Match struct {
	Type     MatchType
	Pods     []podmodel.ID
	IPBlocks []IPBlock
	Ports    []Port
}

// NewMockPolicyConfigurator is a constructor for MockPolicyConfigurator.
func NewMockPolicyConfigurator(log logging.Logger) *MockPolicyConfigurator {
	return &MockPolicyConfigurator{
		Log:    log,
		config: make(map[podmodel.ID]ContivPolicies),
	}
}

func (mpct *MockPolicyConfiguratorTxn) Configure(pod podmodel.ID, policies []*ContivPolicy) configurator.Txn {
	mpct.Log.WithFields(logging.Fields{
		"pod":      pod,
		"policies": policies,
	}).Debug("PolicyConfigurator Configure()")
	mpct.config[pod] = policies
	return mpct
}

func (mpc *MockPolicyConfigurator) Commit() error {
	return nil
}

func (mpc *MockPolicyConfigurator) NewTxn(resync bool) configurator.Txn {
	return &MockPolicyConfiguratorTxn{
		Log:          mpc.Log,
		resync:       resync,
		configurator: mpc,
		config:       make(map[podmodel.ID]ContivPolicies),
	}
}
