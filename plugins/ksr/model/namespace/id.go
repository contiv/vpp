package namespace

type ID string

func GetID(ns *Namespace) ID {
	if ns != nil {
		return ID(ns.Name)
	}
	return ID("")
}

func (id ID) String() string {
	return string(id)
}
