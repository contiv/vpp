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

package v1

import (
	"github.com/contiv/vpp/plugins/crd/cache/telemetrymodel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CRD Constants
const (
	CRDGroup                          string = "contivtelemetry.vpp"
	CRDGroupVersion                   string = "v1"
	CRDContivTelemetryReport          string = "contivtelemetryreport"
	CRDContivTelemetryReportPlural    string = "contivtelemetryreports"
	CRDFullContivTelemetryReportsName string = CRDContivTelemetryReportPlural + "." + CRDGroup
)

// ContivTelemetryReport describes contiv telemetry custom resource
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ContivTelemetryReport struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	metav1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Spec is the custom resource spec
	Spec   ContivTelemetryReportSpec   `json:"spec,omitempty"`
	Status ContivTelemetryReportStatus `json:"status,omitempty"`
}

// ContivTelemetryReportSpec is the spec for the contiv telemetry resource
type ContivTelemetryReportSpec struct {
	ReportPollingPeriodSeconds uint32 `json:"report_polling_period_seconds"`
}

// ContivTelemetryReportList is a list of ContivTelemetryReport resource
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ContivTelemetryReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ContivTelemetryReport `json:"items"`
}

// ContivTelemetryReportStatus is the state for the contiv telemetry report
type ContivTelemetryReportStatus struct {
	Nodes   []telemetrymodel.Node  `json:"nodes"`
	Reports telemetrymodel.Reports `json:"reports"`
}
