package runtime

import (
	"k8s.io/kubernetes/pkg/kubelet/apis/cri"
)

// RuntimeService interface should be implemented by a container runtime.
// The methods should be thread-safe.
type RuntimeService interface {
	cri.RuntimeService

	// ServiceName method is used to log out with service's name
	ServiceName() string
}

// ImageManagerService interface should be implemented by a container image manager.
// The methods should be thread-safe.
type ImageManagerService interface {
	cri.ImageManagerService

	// ServiceName method is used to log out with service's name
	ServiceName() string
}
