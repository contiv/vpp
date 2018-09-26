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

package ipam

import "github.com/contiv/vpp/plugins/contiv/ipam/model"

//go:generate protoc -I ./model --gogo_out=plugins=grpc:./model ./model/ipam.proto

func (i *IPAM) loadAssignedIPs() error {
	if i.broker == nil {
		i.logger.Info("No broker specified, assigned IPs will not be loaded from persisted storage")
		return nil
	}
	networkPrefix, err := ipv4ToUint32(i.podNetworkIPPrefix.IP)
	if err != nil {
		return err
	}

	it, err := i.broker.ListValues(model.KeyPrefix())
	if err != nil {
		return err
	}
	cnt := 0
	for {
		ip := &model.AllocatedIP{}
		kv, stop := it.GetNext()
		if stop {
			break
		}
		err = kv.GetValue(ip)
		if err != nil {
			return err
		}
		cnt++
		i.assignedPodIPs[ip.ID] = ip.Pod

		diff := int(ip.ID - networkPrefix)
		if i.lastAssigned < diff {
			i.lastAssigned = diff
		}
	}
	i.logger.Infof("%v persisted IPAM items were loaded", cnt)
	return nil
}

func (i *IPAM) saveAssignedIP(ip uint32, pod string) error {
	if i.broker == nil {
		i.logger.Debug("No broker specified, allocated IP will not be persisted")
		return nil
	}
	item := &model.AllocatedIP{ID: ip, Pod: pod}
	return i.broker.Put(model.Key(item.Pod), item)
}

func (i *IPAM) deleteAssignedIP(pod string) error {
	if i.broker == nil {
		i.logger.Debug("No broker specified, released IP will not be persisted")
		return nil
	}
	_, err := i.broker.Delete(model.Key(pod))
	return err
}
