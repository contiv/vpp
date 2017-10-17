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
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"net"
)

type hostCalls interface {
	LinkByName(name string) (netlink.Link, error)
	RouteAdd(route *netlink.Route) error
	AddDefaultRoute(gw net.IP, dev netlink.Link) error
	WithNetNSPath(nspath string, toRun func(ns ns.NetNS) error) error
}

type linuxCalls struct {
}

func (l *linuxCalls) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (l *linuxCalls) RouteAdd(route *netlink.Route) error {
	return netlink.RouteAdd(route)
}

func (l *linuxCalls) AddDefaultRoute(gw net.IP, dev netlink.Link) error {
	return ip.AddDefaultRoute(gw, dev)
}

func (l *linuxCalls) WithNetNSPath(nspath string, toRun func(ns ns.NetNS) error) error {
	return ns.WithNetNSPath(nspath, toRun)
}

type mockLinuxCall struct {
}

func (m *mockLinuxCall) LinkByName(name string) (netlink.Link, error) {
	return &netlink.Dummy{}, nil
}

func (m *mockLinuxCall) RouteAdd(route *netlink.Route) error {
	return nil
}

func (m *mockLinuxCall) AddDefaultRoute(gw net.IP, dev netlink.Link) error {
	return nil
}

func (m *mockLinuxCall) WithNetNSPath(nspath string, toRun func(ns ns.NetNS) error) error {
	return nil
}
