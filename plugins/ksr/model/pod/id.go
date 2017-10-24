package pod

// ID used to uniquely represent a K8s Pod.
type ID struct {
	Name      string
	Namespace string
}

// GetID returns ID of a pod.
func GetID(pod *Pod) ID {
	if pod != nil {
		return ID{Name: pod.Name, Namespace: pod.Namespace}
	}
	return ID{}
}

// String returns a string representation of a pod ID.
func (id ID) String() string {
	return id.Namespace + "/" + id.Name
}
