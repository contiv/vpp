module github.com/contiv/vpp

go 1.13

require (
	git.fd.io/govpp.git v0.2.1-0.20191115113328-e45d8802fd8d
	github.com/Microsoft/go-winio v0.4.12 // indirect
	github.com/apparentlymart/go-cidr v0.0.0-20170616213631-2bd8b58cf427
	github.com/boltdb/bolt v1.3.2-0.20180302180052-fd01fc79c553 // indirect
	github.com/containerd/continuity v0.0.0-20181203112020-004b46473808 // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.7.5
	github.com/docker/docker v1.4.2-0.20180620002508-3dfb26ab3cbf // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/libnetwork v0.8.0-dev.2.0.20180726175142-9ffeaf7d8b64 // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/fluent/fluent-logger-golang v1.4.0 // indirect
	github.com/fsouza/go-dockerclient v1.2.2
	github.com/ghodss/yaml v1.0.0
	github.com/go-errors/errors v1.0.1
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/gorilla/mux v1.7.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/ligato/cn-infra v2.2.1-0.20191030081411-42c7431fdca1+incompatible
	github.com/namsral/flag v1.7.4-pre
	github.com/onsi/gomega v1.5.0
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.3
	github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90
	github.com/safchain/ethtool v0.0.0-20170622225139-7ff1ba29eca2
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/tinylib/msgp v1.1.0 // indirect
	github.com/unrolled/render v1.0.1-0.20190325150441-1ac792296fd4
	github.com/vishvananda/netlink v1.0.1-0.20190319163122-f504738125a5
	github.com/wadey/gocovmerge v0.0.0-20160331181800-b5bfa59ec0ad // indirect
	go.ligato.io/vpp-agent/v2 v2.5.0-alpha.0.20200108085843-0e2148d3dd11
	golang.org/x/net v0.0.0-20190918130420-a8b05e9114ab
	golang.org/x/sys v0.0.0-20200107162124-548cf772de50
	google.golang.org/grpc v1.24.0
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0
	k8s.io/apiextensions-apiserver v0.0.0
	k8s.io/apimachinery v0.0.0
	k8s.io/client-go v0.0.0
	k8s.io/kubernetes v1.16.0
)

// pin kubernetes version to 1.16
replace (
	k8s.io/api => k8s.io/api v0.0.0-20191004120104-195af9ec3521
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191205124210-07afe84a85e4
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191028221656-72ed19daf4bb
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191205122933-ebfe712c1fff
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20191004123735-6bff60de4370
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191114101535-6c5935290e33
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20191004125000-f72359dfc58e
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.0.0-20191004124811-493ca03acbc1
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20191004115455-8e001e5d1894
	k8s.io/component-base => k8s.io/component-base v0.0.0-20191004121439-41066ddd0b23
	k8s.io/cri-api => k8s.io/cri-api v0.0.0-20190828162817-608eb1dad4ac
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.0.0-20191004125145-7118cc13aa0a
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20191205123210-2c2890b1bb12
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.0.0-20191004124629-b9859bb1ce71
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.0.0-20191004124112-c4ee2f9e1e0a
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.0.0-20191004124444-89f3bbd82341
	k8s.io/kubectl => k8s.io/kubectl v0.0.0-20191004125858-14647fd13a8b
	k8s.io/kubelet => k8s.io/kubelet v0.0.0-20191004124258-ac1ea479bd3a
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.0.0-20191207050024-0fd2720a0db9
	k8s.io/metrics => k8s.io/metrics v0.0.0-20191004123543-798934cf5e10
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.0.0-20191205123445-8deb8ea9603c
)

// fix compatibility issue in containernetworking
replace github.com/containernetworking/cni => github.com/containernetworking/cni v0.6.0
