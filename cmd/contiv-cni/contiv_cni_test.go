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

package main

import (
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/contiv/vpp/plugins/contiv/model/cni"
	"github.com/onsi/gomega"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	. "github.com/onsi/gomega"
)

const (
	testServerPort = ":59111"
)

type testCNIServer struct{}

// The request to add a container to network.
func (s *testCNIServer) Add(context.Context, *cni.CNIRequest) (*cni.CNIReply, error) {
	fmt.Println("ADD called")
	return &cni.CNIReply{
		Result: 0,
		Error:  "",
		Interfaces: []*cni.CNIReply_Interface{
			{
				Name: "eth0",
				IpAddresses: []*cni.CNIReply_Interface_IP{
					{
						Address: "192.168.1.53/24",
						Version: cni.CNIReply_Interface_IP_IPV4,
						Gateway: "192.168.1.1",
					},
					{
						Address: "2001:db8::68/64",
						Version: cni.CNIReply_Interface_IP_IPV6,
						Gateway: "2001:db8::1",
					},
				},
			},
		},
		Routes: []*cni.CNIReply_Route{
			{
				Dst: "192.168.1.0/24",
				Gw:  "192.168.1.1",
			},
			{
				Dst: "2001:db8::68/64",
				Gw:  "2001:db8::1",
			},
		},
		Dns: []*cni.CNIReply_DNS{
			{
				Nameservers: []string{"8.8.8.8"},
			},
		},
	}, nil
}

// The request to delete a container from network.
func (s *testCNIServer) Delete(context.Context, *cni.CNIRequest) (*cni.CNIReply, error) {
	fmt.Println("DELETE called")
	return &cni.CNIReply{
		Result: 0,
		Error:  "",
	}, nil
}

func runTestGrpcServer() {
	lis, err := net.Listen("tcp", testServerPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	cni.RegisterRemoteCNIServer(s, &testCNIServer{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func TestCNIAddDelete(t *testing.T) {
	gomega.RegisterTestingT(t)

	go runTestGrpcServer()

	conf := `{
	"cniVersion": "0.3.1",
	"type": "contiv-cni",
	"grpcServer": "localhost%s"
}`
	conf = fmt.Sprintf(conf, testServerPort)

	err := cmdAdd(&skel.CmdArgs{StdinData: []byte(conf)})
	Expect(err).ShouldNot(HaveOccurred())

	err = cmdDel(&skel.CmdArgs{StdinData: []byte(conf)})
	Expect(err).ShouldNot(HaveOccurred())
}
