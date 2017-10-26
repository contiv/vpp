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

package contiv

import (
	"context"
	"testing"

	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contiv/containeridx"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/contiv/vpp/plugins/kvdbproxy"
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging/logroot"
	"github.com/onsi/gomega"
)

const (
	containerID = "sadfja813227wdhfjkh2319784dgh"
	podName     = "ubuntu"
)

var req = cni.CNIRequest{
	Version:          "0.2.3",
	InterfaceName:    "eth0",
	ContainerId:      containerID,
	NetworkNamespace: "/var/run/2345243",
	ExtraArguments:   "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=" + podName + ";K8S_POD_INFRA_CONTAINER_ID=7d673108b0ff9b2f59f977ca5f4cef347cb9ca66888614068882fbfaba4de752",
}

func TestVeth1NameFromRequest(t *testing.T) {
	gomega.RegisterTestingT(t)

	txns := localclient.NewTxnTracker()

	server := newRemoteCNIServer(logroot.StandardLogger(),
		txns.NewDataChangeTxn,
		&kvdbproxy.Plugin{},
		nil,
		nil,
		nil)

	hostIfName := server.veth1HostIfNameFromRequest(&req)
	gomega.Expect(hostIfName).To(gomega.BeEquivalentTo("eth0"))
}

func TestAdd(t *testing.T) {
	gomega.RegisterTestingT(t)

	txns := localclient.NewTxnTracker()
	configuredContainers := containeridx.NewConfigIndex(logroot.StandardLogger(), core.PluginName("Plugin-name"), "title")

	server := newRemoteCNIServer(logroot.StandardLogger(),
		txns.NewDataChangeTxn,
		kvdbproxy.NewKvdbsyncMock(),
		configuredContainers,
		nil,
		nil)
	server.hostCalls = &mockLinuxCalls{}

	reply, err := server.Add(context.Background(), &req)

	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

	gomega.Expect(len(txns.PendingTxns)).To(gomega.BeEquivalentTo(0))
	gomega.Expect(len(txns.CommittedTxns)).To(gomega.BeEquivalentTo(2))
	// TODO add asserts for txns / currently applied config

	res := configuredContainers.LookupPodName(podName)
	gomega.Expect(len(res)).To(gomega.BeEquivalentTo(1))
	gomega.Expect(res).To(gomega.ContainElement(containerID))

	// TODO clear txnTracker

	reply, err = server.Delete(context.Background(), &req)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(reply).NotTo(gomega.BeNil())

}
