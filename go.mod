module github.com/contiv/vpp

go 1.13

require (
	git.fd.io/govpp.git v0.3.1
	github.com/Microsoft/go-winio v0.4.12 // indirect
	github.com/apparentlymart/go-cidr v0.0.0-20170616213631-2bd8b58cf427
	github.com/containerd/continuity v0.0.0-20181203112020-004b46473808 // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.7.5
	github.com/docker/docker v1.4.2-0.20180620002508-3dfb26ab3cbf // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/fluent/fluent-logger-golang v1.4.0 // indirect
	github.com/fsouza/go-dockerclient v1.2.2
	github.com/ghodss/yaml v1.0.0
	github.com/go-errors/errors v1.0.1
	github.com/golang/protobuf v1.3.3
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/gorilla/mux v1.7.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/namsral/flag v1.7.4-pre
	github.com/onsi/gomega v1.7.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.0.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/safchain/ethtool v0.0.0-20170622225139-7ff1ba29eca2
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/unrolled/render v1.0.1-0.20190325150441-1ac792296fd4
	github.com/vishvananda/netlink v1.0.1-0.20190319163122-f504738125a5
	go.ligato.io/cn-infra/v2 v2.5.0-alpha.0.20200313154441-b0d4c1b11c73
	go.ligato.io/vpp-agent/v3 v3.1.0
	golang.org/x/net v0.0.0-20200226121028-0de0cce0169b
	golang.org/x/sys v0.0.0-20200317113312-5766fd39f98d
	google.golang.org/grpc v1.27.1
	k8s.io/api v0.17.1
	k8s.io/apiextensions-apiserver v0.0.0
	k8s.io/apimachinery v0.17.1
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/kubelet v0.0.0
	k8s.io/kubernetes v1.17.1
)

replace (
	k8s.io/api => k8s.io/api v0.17.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.17.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.1
	k8s.io/apiserver => k8s.io/apiserver v0.17.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.17.1
	k8s.io/client-go => k8s.io/client-go v0.17.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.17.1
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.17.1
	k8s.io/code-generator => k8s.io/code-generator v0.17.1
	k8s.io/component-base => k8s.io/component-base v0.17.1
	k8s.io/cri-api => k8s.io/cri-api v0.17.1
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.17.1
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.17.1
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.17.1
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.17.1
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.17.1
	k8s.io/kubectl => k8s.io/kubectl v0.17.1
	k8s.io/kubelet => k8s.io/kubelet v0.17.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.17.1
	k8s.io/metrics => k8s.io/metrics v0.17.1
	k8s.io/node-api => k8s.io/node-api v0.17.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.17.1
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.17.1
	k8s.io/sample-controller => k8s.io/sample-controller v0.17.1
)

// fix compatibility issue in containernetworking
replace github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0
