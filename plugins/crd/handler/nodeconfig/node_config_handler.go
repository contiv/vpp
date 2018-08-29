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

package nodeconfig

// NodeConfigHandler handler implements Handler interface,
// print each event with JSON format
type NodeConfigHandler struct {
}

// Init initializes handler configuration
// Do nothing for default handler
func (nch *NodeConfigHandler) Init() error {
	return nil
}

// ObjectCreated is called when a CRD object is created
func (nch *NodeConfigHandler) ObjectCreated(obj interface{}) {

}

// ObjectDeleted is called when a CRD object is deleted
func (nch *NodeConfigHandler) ObjectDeleted(obj interface{}) {

}

// ObjectUpdated is called when a CRD object is updated
func (nch *NodeConfigHandler) ObjectUpdated(oldObj, newObj interface{}) {

}
