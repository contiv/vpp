module github.com/contiv/vpp

go 1.13

require (
	git.fd.io/govpp.git v0.2.1-0.20200131102335-2df59463fcbb
	github.com/Microsoft/go-winio v0.4.12 // indirect
	github.com/apparentlymart/go-cidr v0.0.0-20170616213631-2bd8b58cf427
	github.com/boltdb/bolt v1.3.2-0.20180302180052-fd01fc79c553 // indirect
	github.com/containerd/continuity v0.0.0-20181203112020-004b46473808 // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.7.5
	github.com/coreos/etcd v3.3.13+incompatible // indirect
	github.com/docker/docker v1.4.2-0.20180620002508-3dfb26ab3cbf // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/fluent/fluent-logger-golang v1.4.0 // indirect
	github.com/fsouza/go-dockerclient v1.2.2
	github.com/ghodss/yaml v1.0.0
	github.com/go-errors/errors v1.0.1
	github.com/golang/protobuf v1.3.3
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/gorilla/mux v1.7.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/ligato/cn-infra v2.2.1-0.20191030081411-42c7431fdca1+incompatible
	github.com/namsral/flag v1.7.4-pre
	github.com/onsi/gomega v1.7.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.0.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/safchain/ethtool v0.0.0-20170622225139-7ff1ba29eca2
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/unrolled/render v1.0.1-0.20190325150441-1ac792296fd4
	github.com/vishvananda/netlink v1.0.1-0.20190319163122-f504738125a5
	github.com/wadey/gocovmerge v0.0.0-20160331181800-b5bfa59ec0ad // indirect
	go.ligato.io/vpp-agent/v3 v3.0.0
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/sys v0.0.0-20200117145432-59e60aa80a0c
	google.golang.org/grpc v1.27.0
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
