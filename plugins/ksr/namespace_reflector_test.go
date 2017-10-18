package ksr

import (
	"sync"
	"testing"

	"github.com/onsi/gomega"

	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	proto "github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/ligato/cn-infra/flavors/local"
)

var k8sListWatch *mockK8sListWatch
var keyProtoValWriter *mockKeyProtoValWriter

func TestNamespaceReflector(t *testing.T) {
	gomega.RegisterTestingT(t)

	flavorLocal := &local.FlavorLocal{}
	flavorLocal.Inject()

	k8sListWatch = &mockK8sListWatch{}
	keyProtoValWriter = newMockKeyProtoValWriter()
	nsReflector := &NamespaceReflector{
		ReflectorDeps: ReflectorDeps{
			Log:          flavorLocal.LoggerFor("ns-reflector"),
			K8sClientset: &kubernetes.Clientset{},
			K8sListWatch: k8sListWatch,
			Publish:      keyProtoValWriter,
		},
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	err := nsReflector.Init(stopCh, &wg)
	gomega.Expect(err).To(gomega.BeNil())

	t.Run("newNamespace", testNewNamespace)
	keyProtoValWriter.ClearDs()
	// TODO: add more
}

func testNewNamespace(t *testing.T) {
	ns := &core_v1.Namespace{}
	ns.Name = "namespace1"
	ns.Labels = make(map[string]string)
	ns.Labels["role"] = "mgmt"
	ns.Labels["privileged"] = "true"
	k8sListWatch.Add(ns)

	nsProto := &proto.Namespace{}
	err := keyProtoValWriter.GetValue(proto.Key(ns.GetName()), nsProto)
	gomega.Expect(err).To(gomega.BeNil())
	gomega.Expect(nsProto).NotTo(gomega.BeNil())
	gomega.Expect(nsProto.Name).To(gomega.Equal(ns.GetName()))
	gomega.Expect(nsProto.Label).To(gomega.HaveLen(2))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "role", Value: "mgmt"}))
	gomega.Expect(nsProto.Label).To(gomega.ContainElement(&proto.Namespace_Label{Key: "privileged", Value: "true"}))
}
