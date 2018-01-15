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

//go:generate binapi-generator --input-file=/usr/share/vpp/api/nat.api.json --output-dir=bin_api

package configurator

import (
	"fmt"

	"github.com/contiv/vpp/plugins/service/configurator/bin_api/nat"
)

// enableNat44Forwarding enables NAT44 forwarding, meaning that traffic not matching
// any NAT rules will be just forwarded and not dropped.
func (sc *ServiceConfigurator) enableNat44Forwarding() error {
	req := &nat.Nat44ForwardingEnableDisable{
		Enable: 1,
	}
	reply := &nat.Nat44ForwardingEnableDisableReply{}
	err := sc.GoVPPChan.SendRequest(req).ReceiveReply(reply)
	if reply.Retval != 0 {
		return fmt.Errorf("attempt to enable NAT44 forwarding returned non zero error code (%v)",
			reply.Retval)
	}
	return err
}
