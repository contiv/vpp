/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
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

package utils

import (
	nodeconfig "github.com/contiv/vpp/plugins/crd/pkg/apis/nodeconfig/v1"
	telemetry "github.com/contiv/vpp/plugins/crd/pkg/apis/telemetry/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetObjectMetaData returns metadata of a given k8s object
func GetObjectMetaData(obj interface{}) meta.ObjectMeta {

	var objectMeta meta.ObjectMeta

	switch object := obj.(type) {
	case *telemetry.TelemetryReport:
		objectMeta = object.ObjectMeta
	case *nodeconfig.NodeConfig:
		objectMeta = object.ObjectMeta
	}

	return objectMeta
}
