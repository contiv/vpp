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

package controller

import (
	"github.com/contiv/vpp/plugins/crd/controller/nodeconfig"
	"github.com/contiv/vpp/plugins/crd/controller/telemetry"
	"github.com/ligato/cn-infra/infra"

	//"github.com/contiv/vpp/plugins/crd/controller/telemetry"
	crdClientSet "github.com/contiv/vpp/plugins/crd/pkg/client/clientset/versioned"
	"github.com/ligato/cn-infra/logging"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
)

// ContivTelemetryController struct defines how a controller should encapsulate
// logging, client connectivity, informing (list and watching) queueing, and
// handling of resource changes
type ContivCRDController struct {
	Deps

	K8sClient *kubernetes.Clientset
	CrdClient *crdClientSet.Clientset
	APIClient *apiextcs.Clientset

	telemetryController  *controller.TelemetryController
	nodeConfigController *controller.NodeConfigController
}

// Deps defines dependencies for the CRD plugin
type Deps struct {
	infra.PluginDeps
	Log logging.Logger
}

// Init performs the initialization of ContivTelemetryController
func (ctc *ContivCRDController) Init() error {
	ctc.nodeConfigController = &controller.NodeConfigController{
		Deps: controller.Deps{
			Log: ctc.Log.
		},
	}
	return nil
}
