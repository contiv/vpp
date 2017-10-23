package pod

type ID struct {
	Name      string
	Namespace string
}

func GetID(pod *Pod) ID {
	if pod != nil {
		return ID{Name: pod.Name, Namespace: pod.Namespace}
	}
	return ID{}
}

func (id ID) String() string {
	return id.Namespace + "/"  + id.Name
}