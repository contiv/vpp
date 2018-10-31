package main

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"os"
	"os/signal"
)

func main() {

	fmt.Println("Hello, playground")

	/*
	   	veth := &netlink.Veth{
	   		LinkAttrs: netlink.LinkAttrs{
	   			Name:   "veth1",
	   			TxQLen: 0,
	   		},
	   		PeerName: "veth2",
	   	}

	   	// Create the veth pair.
	   	netlink.LinkAdd(veth)

	   	link, err := netlink.LinkByName("veth1")
	   	if err != nil {
	   		fmt.Println(err)
	   	}
	   	err = netlink.LinkSetAlias(link, "" +
	   "my-veth1-suuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuper-loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong-alias")
	   	if err != nil {
	   		fmt.Println(err)
	   	}
	*/
	link, _ := netlink.LinkByName("enp0s9")
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
	for _, addr := range addrs {
		fmt.Printf("%v - %d, %d\n", addr.IP, addr.Flags, addr.Scope)
	}
	arpEntry := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    netlink.FAMILY_V4,
		State:     netlink.NUD_PERMANENT,
	}
	arpEntry.IP = net.ParseIP("10.3.1.50")
	arpEntry.HardwareAddr, _ = net.ParseMAC("aa:bb:cc:11:22:55")
	netlink.NeighSet(arpEntry)

	_, dst, _ := net.ParseCIDR("10.7.0.0/24")
	netlink.RouteAdd(&netlink.Route{
		//LinkIndex: link.Attrs().Index,
		Scope: netlink.SCOPE_UNIVERSE,
		Dst:   dst,
		//Src:   net.ParseIP("11.11.11.11"),
		Gw:       net.ParseIP("10.3.1.1"),
		Priority: 20,
	})

	link2, _ := netlink.LinkByName("enp0s3")
	dummyLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: link2.Attrs().Index}}
	routes, _ := netlink.RouteList(dummyLink, netlink.FAMILY_V6)
	for _, route := range routes {
		fmt.Printf("route: %v\n", route)
		//fmt.Printf("route: %d, %d, %v, %v, %d, %d\n", route.LinkIndex, route.Scope, route.Dst, route.Gw, route.Priority, route.Protocol)
	}

	interfaces, _ := netlink.LinkList()
	for _, intf := range interfaces {
		fmt.Printf("%s - %d, %s\n", intf.Attrs().Name, intf.Attrs().Flags&net.FlagUp, intf.Attrs().Alias)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})

	netlink.LinkSubscribe(ch, done)

	terminate := false
	for {
		select {
		case update := <-ch:
			state := ""
			switch update.Attrs().OperState {
			case netlink.OperUnknown:
				state = "OperUnknown"
			case netlink.OperNotPresent:
				state = "OperNotPresent"
			case netlink.OperDown:
				state = "OperDown"
			case netlink.OperLowerLayerDown:
				state = "OperLowerLayerDown"
			case netlink.OperTesting:
				state = "OperTesting"
			case netlink.OperDormant:
				state = "OperDormant"
			case netlink.OperUp:
				state = "OperUp"
			}
			link := update.Link
			veth, isVeth := link.(*netlink.Veth)
			fmt.Printf("Update name=%s, type=%s, state=%s, veth-peer=%s, isVeth=%t\n", update.Attrs().Name, update.Type(), state, veth.PeerName, isVeth)
		case <-c:
			close(done)
			terminate = true
		}
		if terminate {
			break
		}
	}
}
