package contiv

import "net"

// API for other plugins to query network-related information.
type API interface {
	// GetIfName looks up logical interface name that corresponds to the interface
	// associated with the given pod.
	GetIfName(podNamespace string, podName string) (name string, exists bool)

	// GetPodNetwork provides subnet used for allocating pod IP addresses on this host node.
	GetPodNetwork() *net.IPNet
}
