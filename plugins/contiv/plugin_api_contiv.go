package contiv

import "net"

// API for other plugins to query network-related information.
type API interface {
	// GetIfName looks up logical interface name that corresponds to the interface
	// associated with the given pod.
	GetIfName(podNamespace string, podName string) (name string, exists bool)

	// GetNsIndex returns the index of the VPP session namespace associated
	// with the given pod.
	GetNsIndex(podNamespace string, podName string) (nsIndex uint32, exists bool)

	// GetPodNetwork provides subnet used for allocating pod IP addresses on this host node.
	GetPodNetwork() *net.IPNet

	// IsTCPstackDisabled returns true if the TCP stack is disabled and only VETHSs/TAPs are configured
	IsTCPstackDisabled() bool
}
