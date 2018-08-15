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

package api

import (
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	"time"
)

const (
	// GlobalMsg defines the report bin where to put global (i.e.
	// non-node-specific) status/error messages
	GlobalMsg = "global"
)

// Report is the interface for collecting validation status/error messages
// and for printing them out.
type Report interface {
	LogErrAndAppendToNodeReport(nodeName string, errString string)
	AppendToNodeReport(nodeName string, errString string)
	SetTimeStamp(time time.Time)
	GetTimeStamp() time.Time
	Clear()
	Print()
	RetrieveReport() telemetrymodel.Reports
}
