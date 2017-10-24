package policy

// ID used to uniquely represent a K8s Policy.
type ID struct {
	Name      string
	Namespace string
}

// GetID returns ID of a policy.
func GetID(policy *Policy) ID {
	if policy != nil {
		return ID{Name: policy.Name, Namespace: policy.Namespace}
	}
	return ID{}
}

// String returns a string representation of a policy ID.
func (id ID) String() string {
	return id.Namespace + "/" + id.Name
}
