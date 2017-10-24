package namespace

// ID used to uniquely represent a K8s Namespace.
type ID string

// GetID returns ID of a namespace.
func GetID(ns *Namespace) ID {
	if ns != nil {
		return ID(ns.Name)
	}
	return ID("")
}

// String returns a string representation of a namespace ID.
func (id ID) String() string {
	return string(id)
}
