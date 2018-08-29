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

// Handler handler implements Handler interface,
type Handler struct {
}

// Init initializes handler configuration
// NodeConfig Handler will be taking action on resource CRUD
func (h *Handler) Init() error {
	return nil
}

// ObjectCreated is called when a CRD object is created
func (h *Handler) ObjectCreated(obj interface{}) {
	//fmt.Printf("Object created with value: %v", obj)
}

// ObjectDeleted is called when a CRD object is deleted
func (h *Handler) ObjectDeleted(obj interface{}) {
	//fmt.Printf("Object deleted with value: %v", obj)

}

// ObjectUpdated is called when a CRD object is updated
func (h *Handler) ObjectUpdated(obj interface{}) {
	//fmt.Printf("Object updated with value: %v", obj)
}
