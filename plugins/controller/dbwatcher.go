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
	"github.com/ligato/cn-infra/db/keyval"

	"github.com/contiv/vpp/plugins/controller/api"
)

type dbWatcher struct {
}

func NewDBWatcher(localDB, remoteDB keyval.KvProtoPlugin, resources []api.DBResource,
	externalKeyPrefixes []string) *dbWatcher {

	return &dbWatcher{}
}

func (w *dbWatcher) RequestRunTimeResync() error {
	return nil
}

func (w *dbWatcher) Close() {

}
