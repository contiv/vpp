package contiv

// API for other plugins to query network-related information.
type API interface {
	// GetIfName looks up logical interface name that corresponds to the interface
	// associated with the given pod.
	GetIfName(podNamespace string, podName string) (name string, exists bool)

	// GetHostIPAddr returns the IP Address of the host that contiv agent is running.
	GetHostIPAddr() (string, error)
}
