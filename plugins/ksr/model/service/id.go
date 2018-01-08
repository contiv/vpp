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

package service

// ID used to uniquely represent a K8s Service.
type ID struct {
	Name      string
	Namespace string
}

// GetID returns ID of a service.
func GetID(service *Service) ID {
	if service != nil {
		return ID{Name: service.Name, Namespace: service.Namespace}
	}
	return ID{}
}

// String returns a string representation of a service ID.
func (id ID) String() string {
	return id.Namespace + "/" + id.Name
}
