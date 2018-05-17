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

//go:generate protoc -I ./model/stn --go_out=plugins=grpc:./model/stn ./model/stn/stn.proto

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
)

const (
	defaultGRPCServerPort  = 50051 // port where the GRPC STN server listens for client connections
	defaultStatusCheckPort = 9999  // port that STN server is checking to determine contiv-agent liveness

	initStatusCheckTimeout = 30 * time.Second // initial timeout after which the STN server starts checking of the contiv-agent state
	statusCheckInterval    = 1 * time.Second  // periodic interval in which the STN server checks for contiv-agent state
	linkCheckTimeout       = 3 * time.Second  // timeout after which we re-check if the link is in expected state

	configRetryCount = 20                     // number of config attempts in case that an error is returned / config is not applied correctly
	configRetrySleep = 200 * time.Millisecond // sleep interval between individual config retry attempts

	vppTapInterfaceName = "vpp1" // name of the TAP interface which VPP creates once STN is configured
)

var (
	// BuildVersion contains git version hash, set by the Makefile using ldflags during build.
	BuildVersion string
	// BuildDate contains date of the build, set by the Makefile using ldflags during build.
	BuildDate string

	grpcServerPort  = flag.Int("grpc", defaultGRPCServerPort, "port where the GRPC STN server listens for client connections")
	statusCheckPort = flag.Int("statuscheck", defaultStatusCheckPort, "port that STN server is checking to determine contive-agent liveness")
)

// stnServer represents an instance of the STN GRPC server.
type stnServer struct {
	ethTool            *ethtool.Ethtool
	stolenInterfaces   map[string]*interfaceData
	statusCheckStarted bool
	statusCheckEnabled bool
	sync.Mutex
}

// interfaceData holds information about an interface state before "stealing".
type interfaceData struct {
	name        string
	PCIAddress  string
	driver      string
	linkIndex   int
	addresses   []netlink.Addr
	routes      []netlink.Route
	dhcpEnabled bool
}

// newSTNServer returns a new instance of the STN GRPC server.
func newSTNServer() *stnServer {
	return &stnServer{
		stolenInterfaces: map[string]*interfaceData{},
	}
}

// StealInterface implements GRPC StealInterface procedure. It "steals" (unconfigures) an interface
// identified by its name and saves its state for later rollback.
func (s *stnServer) StealInterface(ctx context.Context, req *stn.STNRequest) (*stn.STNReply, error) {
	log.Println("GRPC StealInterface request:", req)

	// unconfigure the interface & remember the original config
	ifData, err := s.unconfigureInterface(req.InterfaceName, req.DhcpEnabled)
	if err != nil {
		log.Println(err)
		return s.grpcReplyError(err), err
	}

	// generate GRPC response
	resp := s.grpcReplyData(ifData)
	log.Println("Returning GRPC data:", resp)

	return resp, nil
}

// ReleaseInterface implements GRPC ReleaseInterface procedure. It releases (configures back)
// a previously "stolen" (unconfigured) interface.
func (s *stnServer) ReleaseInterface(ctx context.Context, req *stn.STNRequest) (*stn.STNReply, error) {
	log.Println("GRPC ReleaseInterface request:", req)

	// revert the original interface config
	err := s.revertInterface(req.InterfaceName)
	if err != nil {
		log.Println(err)
		return s.grpcReplyError(err), err
	}

	return s.grpcReplyEmptyOK(), nil
}

// StolenInterfaceInfo implements GRPC StolenInterfaceInfo procedure.
// It returns information about the already stolen interface.
func (s *stnServer) StolenInterfaceInfo(ctx context.Context, req *stn.STNRequest) (*stn.STNReply, error) {
	log.Println("GRPC StolenInterfaceInfo request:", req)

	// find interface data
	ifData, err := s.getStolenInterfaceData(req.InterfaceName)
	if err != nil {
		log.Println(err)
		return s.grpcReplyError(err), err
	}

	// generate GRPC response
	resp := s.grpcReplyData(ifData)
	log.Println("Returning GRPC data:", resp)

	return resp, nil
}

// unconfigureInterface "steals" an interface identified by its name and returns its original config.
func (s *stnServer) unconfigureInterface(ifName string, dhcpEnabled bool) (*interfaceData, error) {
	s.Lock()
	defer s.Unlock()

	// check whether the interface has not been already stolen
	if ifData, ok := s.stolenInterfaces[ifName]; ok {
		log.Printf("Interface %s has been already stolen.", ifName)
		return ifData, nil
	}

	// list existing links
	links, err := netlink.LinkList()
	if err != nil {
		log.Println("Unable to list links:", err)
		return nil, err
	}

	// find link to steal
	for _, l := range links {
		if l.Attrs().Name == ifName {
			// found link matching the interface name, unconfigure it
			ifData, err := s.unconfigureLink(l)
			if err != nil {
				return nil, err
			}
			ifData.dhcpEnabled = dhcpEnabled

			// start asynchronous checking of the VPP-agent state
			s.checkStatusAfterTimeout()
			return ifData, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", ifName)
}

// revertInterface reverts interface config to the state before its stealing.
func (s *stnServer) revertInterface(ifName string) error {
	s.Lock()
	defer s.Unlock()

	if ifData, ok := s.stolenInterfaces[ifName]; ok {
		return s.revertLink(ifData)
	}
	return fmt.Errorf("no previous config found for the interface %s", ifName)
}

// getStolenInterfaceData returns data of the already stolen interface.
func (s *stnServer) getStolenInterfaceData(ifName string) (*interfaceData, error) {
	s.Lock()
	defer s.Unlock()

	// no interface name defined - return the first one
	if ifName == "" {
		for _, i := range s.stolenInterfaces {
			return i, nil
		}
		err := fmt.Errorf("no existing stolen interface data")
		log.Println(err)
		return nil, err
	}

	// find matching interface
	ifData, ok := s.stolenInterfaces[ifName]
	if !ok {
		err := fmt.Errorf("interface %s not found in stolen interface list", ifName)
		log.Println(err)
		return nil, err
	}

	return ifData, nil
}

// unconfigureLink "steals" a link and returns its original config.
func (s *stnServer) unconfigureLink(l netlink.Link) (*interfaceData, error) {
	var err error

	ifData := &interfaceData{
		name:      l.Attrs().Name,
		linkIndex: l.Attrs().Index,
	}

	// retrieve PCI address and current driver name
	ifData.PCIAddress, err = s.ethTool.BusInfo(ifData.name)
	if err != nil {
		log.Printf("Error by retriving interface %s bus info: %v", ifData.name, err)
		return nil, err
	}
	ifData.driver, err = s.ethTool.DriverName(ifData.name)
	if err != nil {
		log.Printf("Error by retriving interface %s driver name: %v", ifData.name, err)
		return nil, err
	}

	// list & unconfigure routes
	routes, err := netlink.RouteList(l, netlink.FAMILY_V4)
	if err != nil {
		log.Printf("Error by listing interface %s routes: %v", ifData.name, err)
		return nil, err
	}
	for _, r := range routes {
		ifData.routes = append(ifData.routes, r)
		err = netlink.RouteDel(&r)
		if err != nil {
			log.Printf("Error by deleting interface %s route: %v", ifData.name, err)
			return nil, err
		}
	}

	// shut down the interface
	err = netlink.LinkSetDown(l)
	if err != nil {
		log.Printf("Error by shutting down the interface %s: %v", ifData.name, err)
		return nil, err
	}

	// list & unconfigure IP addresses (after shutting down, otherwise DHCP may return the IP back)
	ifData.addresses, err = netlink.AddrList(l, netlink.FAMILY_V4)
	if err != nil {
		log.Printf("Error by listing interface %s addresses: %v", ifData.name, err)
		return nil, err
	}
	for _, addr := range ifData.addresses {
		err = netlink.AddrDel(l, &addr)
		if err != nil {
			log.Printf("Error by deleting interface %s IP: %v", ifData.name, err)
			return nil, err
		}
	}

	// remember stolen interface state
	s.stolenInterfaces[ifData.name] = ifData

	return ifData, nil
}

// revertLink reverts a link config to the state before its stealing.
func (s *stnServer) revertLink(ifData *interfaceData) error {
	log.Println("Reverting interface", ifData.name)

	// bind to proper PCI driver
	err := pciDriverBind(ifData.PCIAddress, ifData.driver)
	if err != nil {
		log.Printf("Unable to bind PCI device %s to driver %s", ifData.PCIAddress, ifData.driver)
		return err
	}

	// try to find the link in a loop (some time is needed in case it has been just bound to a new driver)
	link, err := s.findLinkByName(ifData.name)
	if err != nil {
		log.Printf("Error by looking up for interface %s: %v", ifData.name, err)
		return err
	}

	// enable the interface
	err = s.setLinkUp(link)
	if err != nil {
		log.Printf("Error by enabling interface %s: %v", ifData.name, err)
		return err
	}

	if !ifData.dhcpEnabled {
		// configure IP addresses
		for _, addr := range ifData.addresses {
			err = s.setLinkIP(link, addr)
			if err != nil {
				log.Printf("Error by reverting interface %s IP: %v", ifData.name, err)
				return err
			}
		}

		// configure routes
		for _, r := range ifData.routes {
			s.updateLinkInRoute(&r, ifData.linkIndex, link.Attrs().Index)
			err = s.addLinkRoute(link, r)
			if err != nil {
				log.Printf("Error by reverting interface %s route: %v", ifData.name, err)
				return err
			}
		}
	} else {
		log.Printf("DHCP is enabled on the interface %s, leaving IP/route config up to the DHCP client.", ifData.name)
	}

	// check the link status after timeout
	s.checkLinkAfterTimeout(ifData)

	// delete the interface info
	delete(s.stolenInterfaces, ifData.name)
	return nil
}

// checkLinkAfterTimeout checks if the link is in the expected state after the timeout.
func (s *stnServer) checkLinkAfterTimeout(ifData *interfaceData) {
	timer := time.NewTimer(linkCheckTimeout)
	go func() {
		<-timer.C

		// check if the link is in the expected state
		s.checkLinkState(ifData)
	}()
}

// checkLinkState checks if the link is in the expected state.
func (s *stnServer) checkLinkState(ifData *interfaceData) {
	s.Lock()
	defer s.Unlock()

	log.Printf("Checking state of the interface %s", ifData.name)

	// do not check the link if it has been stolen again
	_, ok := s.stolenInterfaces[ifData.name]
	if ok {
		log.Printf("Interface %s stolen again, skipping check.", ifData.name)
		return
	}

	// check interface state
	l, err := s.findLinkByName(ifData.name)
	if err != nil {
		log.Printf("Error by looking up for interface %s: %v", ifData.name, err)
		return
	}
	if l.Attrs().OperState == netlink.OperDown {
		log.Printf("Link is DOWN, trying to put it UP.")
		err = s.setLinkUp(l)
		if err != nil {
			log.Println(err)
		}
		s.checkLinkAfterTimeout(ifData)
		return
	}

	// check interface IP
	for _, addr := range ifData.addresses {
		matched := false
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err == nil {
			for _, a := range addrs {
				if a.Equal(addr) {
					// successfully configured
					matched = true
					break
				}
			}
		}
		if !matched {
			log.Printf("IP %s missing on interface %s, reconfiguring.", addr.String(), ifData.name)
			err = s.setLinkIP(l, addr)
			if err != nil {
				log.Println(err)
			}
			s.checkLinkAfterTimeout(ifData)
			return
		}
	}

	// check routes
	for _, route := range ifData.routes {
		s.updateLinkInRoute(&route, ifData.linkIndex, l.Attrs().Index)
		matched := false
		routes, err := netlink.RouteList(l, netlink.FAMILY_V4)
		if err == nil {
			for _, r := range routes {
				if r.String() == route.String() {
					// successfully configured
					matched = true
					break
				}
			}
		}
		if !matched {
			log.Printf("Route %s missing on interface %s, reconfiguring.", route.String(), ifData.name)
			err = s.addLinkRoute(l, route)
			if err != nil {
				log.Println(err)
			}
			s.checkLinkAfterTimeout(ifData)
			return
		}
	}

	log.Printf("Interface %s is in desired state.", ifData.name)
}

// findLinkByName finds link by interface name. If link cannot be found, retries configRetryCount times.
func (s *stnServer) findLinkByName(ifName string) (netlink.Link, error) {
	for i := 0; i < configRetryCount; i++ {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			if i < configRetryCount-1 {
				// wait & retry
				log.Printf("IP link lookup attempt %d failed, retry", i+1)
				time.Sleep(configRetrySleep)
				continue
			} else {
				// not able to find the link in multiple retries
				log.Printf("Error by looking up for interface %s: %v", ifName, err)
				return nil, err
			}
		}
		// found the link
		return link, nil
	}
	return nil, nil
}

// setLinkUp moves provided link to UP state. It also checks whether the state change has been successful and retries if not.
func (s *stnServer) setLinkUp(link netlink.Link) error {
	log.Printf("Setting interface %s (idx %d) to UP state", link.Attrs().Name, link.Attrs().Index)

	for i := 0; i < configRetryCount; i++ {
		// set link to UP state
		err := netlink.LinkSetUp(link)
		if err != nil {
			log.Printf("Error by enabling interface %s: %v", link.Attrs().Name, err)
			return err
		}

		// check whether the link is UP
		l, err := netlink.LinkByName(link.Attrs().Name)
		if err == nil {
			if l.Attrs().OperState != netlink.OperDown {
				// successfully configured
				return nil
			}
		}
		// not configured successfully
		if i < configRetryCount-1 {
			// wait & retry
			log.Printf("Link UP check attempt %d failed, retry", i+1)
			time.Sleep(configRetrySleep)
			continue
		} else {
			// not able to configure in multiple retries
			log.Printf("Error by enabling interface %s: not able to enable in %d retries", link.Attrs().Name, i+1)
			return err
		}
	}

	return nil
}

// setLinkIP sets an IP address on provided link. It also checks whether the config has been successfully applied and retries if not.
func (s *stnServer) setLinkIP(link netlink.Link, addr netlink.Addr) error {
	log.Printf("Adding IP address %s to interface %s (idx %d)", addr.String(), link.Attrs().Name, link.Attrs().Index)

	for i := 0; i < configRetryCount; i++ {
		// configure the IP address
		err := netlink.AddrAdd(link, &addr)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EEXIST {
				log.Printf("%s: IP %s already exists, skipping", link.Attrs().Name, addr.IP.String())
				return nil
			}
			log.Printf("Error by configuring interface %s address %s: %v", link.Attrs().Name, addr.IP.String(), err)
			return err
		}

		// check whether address has been configured properly
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err == nil {
			for _, a := range addrs {
				if a.Equal(addr) {
					// successfully configured
					return nil
				}
			}
		}

		// not configured successfully
		if i < configRetryCount-1 {
			// wait & retry
			log.Printf("IP address config check attempt %d failed, retry", i+1)
			time.Sleep(configRetrySleep)
			continue
		} else {
			// not able to configure in multiple retries
			log.Printf("Error by configuring interface %s address %s: not able to configure in %d retries", link.Attrs().Name, addr.IP.String(), i+1)
			return err
		}
	}

	return nil
}

// addLinkRoute adds a new route referring the provided link. It also checks whether the config has been successfully applied and retries if not.
func (s *stnServer) addLinkRoute(link netlink.Link, route netlink.Route) error {
	log.Printf("Adding route via interface %s: %v", link.Attrs().Name, route)

	for i := 0; i < configRetryCount; i++ {
		// configure the route
		err := netlink.RouteAdd(&route)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EEXIST {
				log.Printf("%s: route already exists, skipping (%v)", link.Attrs().Name, route)
				return nil
			}
			log.Printf("Error by reverting interface %s route %v: %v", link.Attrs().Name, route, err)
			return err
		}

		// check whether the route has been configured properly
		routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
		if err == nil {
			for _, r := range routes {
				if r.String() == route.String() {
					// successfully configured
					return nil
				}
			}
		}

		// not configured successfully
		if i < configRetryCount-1 {
			// wait & retry
			log.Printf("Route config check attempt %d failed, retry", i+1)
			time.Sleep(configRetrySleep)
			continue
		} else {
			// not able to configure in multiple retries
			log.Printf("Error by reverting interface %s route %v in %d retries", link.Attrs().Name, route, i+1)
			return err
		}
	}

	return nil
}

// updateLinkInRoute updates link indexes in the old route with the new index of the link.
func (s *stnServer) updateLinkInRoute(r *netlink.Route, oldLinkIndex int, newLinkIndex int) {
	r.LinkIndex = newLinkIndex
	for _, nh := range r.MultiPath {
		if nh.LinkIndex == oldLinkIndex {
			nh.LinkIndex = newLinkIndex
		}
	}
}

// revertAllLinks reverts all links config to the state before their stealing.
func (s *stnServer) revertAllLinks() {
	for _, i := range s.stolenInterfaces {
		s.revertLink(i)
	}
}

// checkStatusAfterTimeout starts checking the contiv-agent state after the init timeout.
func (s *stnServer) checkStatusAfterTimeout() {
	timer := time.NewTimer(initStatusCheckTimeout)
	go func() {
		<-timer.C

		s.Lock()
		defer s.Unlock()

		s.statusCheckEnabled = true
		if !s.statusCheckStarted {
			s.startLinkStatusCheckLoop()
		}
	}()
}

// startLinkStatusCheckLoop starts checks of the status of the VPP TAP interface.
func (s *stnServer) startLinkStatusCheckLoop() {
	// look up for the TAP interface
	_, err := s.findLinkByName(vppTapInterfaceName)
	if err != nil {
		log.Printf("Error by looking up for interface %s: %v", vppTapInterfaceName, err)
		// revert all interfaces
		s.revertAllLinks()
		return
	}

	log.Printf("Subscribing for interface %s status updates.", vppTapInterfaceName)
	s.statusCheckStarted = true

	// start watching for link notifications
	updCh := make(chan netlink.LinkUpdate)
	doneCh := make(chan struct{})
	err = netlink.LinkSubscribe(updCh, doneCh)
	if err != nil {
		log.Printf("Error by subscribing for interface updates: %v", err)
		// revert all interfaces
		s.revertAllLinks()
		return
	}

	// watch for TAP interface link notifications
	go func() {
		for linkNotif := range updCh {
			if s.statusCheckEnabled {
				linkAttrs := linkNotif.Link.Attrs()
				if linkAttrs == nil {
					continue
				}
				if linkAttrs.Name == vppTapInterfaceName {
					log.Printf("Interface %s state change: %v", vppTapInterfaceName, linkNotif.Link.Attrs().OperState)
					if linkAttrs.OperState == netlink.OperDown {
						// stop further checking
						s.statusCheckEnabled = false

						// revert all interfaces
						s.revertAllLinks()
					}
				}
			}
		}
	}()
}

// statusCheck starts a goroutine that periodically checks the status of contiv-agent.
func (s *stnServer) startAgentStatusCheckLoop() {
	log.Println("Starting periodic check of status of the contiv-agent")

	s.statusCheckStarted = true

	ticker := time.NewTicker(statusCheckInterval)
	go func() {
		for {
			<-ticker.C
			if s.statusCheckEnabled {
				s.checkAgentStatus()
			}
		}
	}()
}

// checkAgentStatus synchronously checks the status of contiv-agent and request interface config rollback in case it is not alive.
func (s *stnServer) checkAgentStatus() {
	conn, err := net.Dial("tcp", fmt.Sprintf(":%d", *statusCheckPort))
	if err != nil {
		log.Printf("Unable to connect to health check probe at port %d, reverting the interfaces", *statusCheckPort)

		s.Lock()
		defer s.Unlock()

		// stop further checking
		s.statusCheckEnabled = false

		// revert all interfaces
		s.revertAllLinks()
	} else {
		conn.Close()
	}
}

// grpcReplyData returns GRPC reply with data filled in from the provided interface data.
func (s *stnServer) grpcReplyData(ifData *interfaceData) *stn.STNReply {
	reply := &stn.STNReply{
		PciAddress: ifData.PCIAddress,
		Result:     0, // 0 = success
	}

	// fill-in IP addresses
	for _, addr := range ifData.addresses {
		perfLen, _ := addr.Mask.Size()
		reply.IpAddresses = append(reply.IpAddresses, fmt.Sprintf("%s/%d", addr.IP.String(), perfLen))
	}

	// fill-in routes
	for _, r := range ifData.routes {
		route := &stn.STNReply_Route{}
		if r.Dst != nil {
			route.DestinationSubnet = r.Dst.String()
		}
		if len(r.Gw) != 0 {
			route.NextHopIp = r.Gw.String()
		}
		reply.Routes = append(reply.Routes, route)
	}

	return reply
}

// grpcReplyEmptyOK returns an empty GRPC reply with success result code.
func (s *stnServer) grpcReplyEmptyOK() *stn.STNReply {
	return &stn.STNReply{
		Result: 0, // 0 = success
	}
}

// grpcReplyError returns a GRPC reply with error information filled in.
func (s *stnServer) grpcReplyError(err error) *stn.STNReply {
	return &stn.STNReply{
		Result: 1, // non-zero = error
		Error:  fmt.Sprintf("%v", err),
	}
}

// main routine of the STN service.
func main() {
	var err error
	flag.Parse()

	log.Printf("Contiv-STN daemon, version %s, build date %s", BuildVersion, BuildDate)

	server := newSTNServer()

	// init ethtool
	server.ethTool, err = ethtool.NewEthtool()
	if err != nil {
		log.Fatalf("failed to init ethtool: %v", err)
	}

	log.Printf("Starting the STN GRPC server at port %d", *grpcServerPort)

	// init GRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *grpcServerPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	stn.RegisterSTNServer(s, server)

	// start the GRPC server in the background
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// wait until SIGINT/SIGTERM signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigs
	log.Printf("%v signal received, exiting", sig)

	// revert links and stop the server
	server.revertAllLinks()
	s.Stop()
	lis.Close()
}
