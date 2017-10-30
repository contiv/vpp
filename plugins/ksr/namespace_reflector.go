package ksr

import (
	"sync"

	proto "github.com/contiv/vpp/plugins/ksr/model/namespace"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

// NamespaceReflector subscribes to K8s cluster to watch for changes
// in the configuration of k8s namespaces.
// Protobuf-modelled changes are published into the selected key-value store.
type NamespaceReflector struct {
	ReflectorDeps

	stopCh <-chan struct{}
	wg     *sync.WaitGroup

	k8sNamespaceStore      cache.Store
	k8sNamespaceController cache.Controller
}

// Init subscribes to K8s cluster to watch for changes in the configuration
// of k8s namespaces. The subscription does not become active until Start()
// is called.
func (nr *NamespaceReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	nr.stopCh = stopCh2
	nr.wg = wg

	restClient := nr.K8sClientset.CoreV1().RESTClient()
	listWatch := nr.K8sListWatch.NewListWatchFromClient(restClient, "namespaces", "", fields.Everything())
	nr.k8sNamespaceStore, nr.k8sNamespaceController = nr.K8sListWatch.NewInformer(
		listWatch,
		&core_v1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ns, ok := obj.(*core_v1.Namespace)
				if !ok {
					nr.Log.Warn("Failed to cast newly created namespace object")
				} else {
					nr.addNamespace(ns)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ns, ok := obj.(*core_v1.Namespace)
				if !ok {
					nr.Log.Warn("Failed to cast removed namespace object")
				} else {
					nr.deleteNamespace(ns)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				nsOld, ok1 := oldObj.(*core_v1.Namespace)
				nsNew, ok2 := newObj.(*core_v1.Namespace)
				if !ok1 || !ok2 {
					nr.Log.Warn("Failed to cast changed namespace object")
				} else {
					nr.updateNamespace(nsNew, nsOld)
				}
			},
		},
	)
	return nil
}

// Start activates the K8s subscription.
func (nr *NamespaceReflector) Start() {
	nr.wg.Add(1)
	go nr.run()
}

// addNamespace adds state data of a newly created K8s namespace into the data
// store.
func (nr *NamespaceReflector) addNamespace(ns *core_v1.Namespace) {
	nr.Log.WithField("ns", ns).Info("K8s namespace added")
	nsProto := nr.namespaceToProto(ns)
	key := proto.Key(ns.GetName())
	err := nr.Publish.Put(key, nsProto)
	if err != nil {
		nr.Log.WithField("err", err).
			Warn("Failed to add k8s namespace state data into the data store")
	}
}

// deleteNamespace deletes state data of a removed K8s namespace from the data
// store.
func (nr *NamespaceReflector) deleteNamespace(ns *core_v1.Namespace) {
	nr.Log.WithField("ns", ns).Info("K8s namespace removed")
	key := proto.Key(ns.GetName())
	_, err := nr.Publish.Delete(key)
	if err != nil {
		nr.Log.WithField("err", err).
			Warn("Failed to remove k8s namespace state data from the data store")
	}
}

// updateNamespace updates state data of a changes K8s namespace in the data
// store.
func (nr *NamespaceReflector) updateNamespace(nsNew, nsOld *core_v1.Namespace) {
	nr.Log.WithFields(map[string]interface{}{"ns-old": nsOld, "ns-new": nsNew}).Info("Namespace updated")
	nsProto := nr.namespaceToProto(nsNew)
	key := proto.Key(nsNew.GetName())
	err := nr.Publish.Put(key, nsProto)
	if err != nil {
		nr.Log.WithField("err", err).
			Warn("Failed to update k8s namespace state data in the data store")
	}
}

// namespaceToProto converts namespace state data from the k8s representation
// into our protobuf-modelled data structure.
func (nr *NamespaceReflector) namespaceToProto(ns *core_v1.Namespace) *proto.Namespace {
	nsProto := &proto.Namespace{}
	nsProto.Name = ns.GetName()
	labels := ns.GetLabels()
	if labels != nil {
		for key, val := range labels {
			nsProto.Label = append(nsProto.Label, &proto.Namespace_Label{Key: key, Value: val})

		}
	}
	return nsProto
}

// run runs k8s subscription in a separate go routine.
func (nr *NamespaceReflector) run() {
	defer nr.wg.Done()
	nr.Log.Info("Namespace reflector is now running")
	nr.k8sNamespaceController.Run(nr.stopCh)
	nr.Log.Info("Stopping Namespace reflector")
}

// Close does nothing for this particular reflector.
func (nr *NamespaceReflector) Close() error {
	return nil
}
