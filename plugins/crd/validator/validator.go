// Copyright (c) 2018 Cisco and/or its affiliates.
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
//

package validator

import (
	"github.com/contiv/vpp/plugins/crd/api"
	"github.com/contiv/vpp/plugins/crd/validator/l2"
	"github.com/contiv/vpp/plugins/crd/validator/l3"
	"github.com/ligato/cn-infra/logging"
)

// Validator is the implementation of the ContivTelemetryProcessor interface.
type Validator struct {
	Deps

	VppCache api.VppCache
	K8sCache api.K8sCache
	Report   api.Report
}

// Deps lists dependencies of PolicyCache.
type Deps struct {
	Log   logging.Logger
	L2Log logging.Logger
	L3Log logging.Logger
}

// Validate performes the validation of all layers of telemetry data
// collected from a Contiv cluster.
func (v *Validator) Validate() {
	l2Validator := &l2.Validator{
		Log:      v.L2Log,
		VppCache: v.VppCache,
		K8sCache: v.K8sCache,
		Report:   v.Report,
	}
	l2Validator.Validate()

	l3Validator := &l3.Validator{
		Log:      v.L3Log,
		VppCache: v.VppCache,
		K8sCache: v.K8sCache,
		Report:   v.Report,
	}
	l3Validator.Validate()

}
