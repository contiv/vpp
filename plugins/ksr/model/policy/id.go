package policy

type ID struct {
	Name      string
	Namespace string
}

func GetID(policy *Policy) ID {
	if policy != nil {
		return ID{Name: policy.Name, Namespace: policy.Namespace}
	}
	return ID{}
}

func (id ID) String() string {
	return id.Namespace + "/" + id.Name
}
