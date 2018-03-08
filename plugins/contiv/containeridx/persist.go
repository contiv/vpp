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

package containeridx

import (
	"github.com/contiv/vpp/plugins/contiv/containeridx/model"
)

func (ci *ConfigIndex) loadConfigureContainers() error {
	if ci.broker == nil {
		ci.logger.Info("No broker specified, configured containers will not be loaded from persisted storage")
		return nil
	}
	it, err := ci.broker.ListValues(container.KeyPrefix())
	if err != nil {
		return err
	}
	cnt := 0
	for {
		item := &container.Persisted{}
		kv, stop := it.GetNext()
		if stop {
			break
		}
		err = kv.GetValue(item)
		if err != nil {
			return err
		}
		cnt++
		ci.mapping.Put(item.ID, item)
	}
	ci.logger.Infof("%v persisted configured container items were loaded", cnt)
	return nil
}

func (ci *ConfigIndex) persistConfiguredContainer(data *container.Persisted) error {
	if ci.broker == nil {
		ci.logger.Debug("No broker specified, configured container will not be persisted")
		return nil
	}
	return ci.broker.Put(container.Key(data.ID), data)
}

func (ci *ConfigIndex) removePersistedConfiguredContainer(id string) error {
	if ci.broker == nil {
		ci.logger.Debug("No broker specified, unconfigured container will not be persisted")
		return nil
	}
	_, err := ci.broker.Delete(container.Key(id))
	return err
}
