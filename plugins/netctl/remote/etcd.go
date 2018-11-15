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

package remote

import (
	"github.com/ligato/cn-infra/config"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/logging/logrus"
	"os"
)

// CreateEtcdClient uses environment variable ETCD_CONFIG or ETCD config file to establish connection
func CreateEtcdClient(configFile string) (*etcd.BytesConnectionEtcd, error) {
	if configFile == "" {
		configFile = os.Getenv("ETCD_CONFIG")
	}

	cfg := &etcd.Config{}
	if configFile != "" {
		if err := config.ParseConfigFromYamlFile(configFile, cfg); err != nil {
			return nil, err
		}
	}

	etcdConfig, err := etcd.ConfigToClient(cfg)
	if err != nil {
		return nil, err
	}

	return etcd.NewEtcdConnectionWithBytes(*etcdConfig, logrus.DefaultLogger())
}
