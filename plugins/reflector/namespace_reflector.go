package reflector

import (
	"sync"

	"k8s.io/apimachinery/pkg/fields"
	clientapi_v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"

	proto "github.com/contiv/vpp/plugins/reflector/model/namespace"
)

type NamespaceReflector struct {
	ReflectorDeps

	stopCh <-chan struct{}
	wg     *sync.WaitGroup

	k8sNamespaceStore      cache.Store
	k8sNamespaceController cache.Controller
}

func (nr *NamespaceReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	nr.stopCh = stopCh2
	nr.wg = wg

	restClient := nr.K8sClientset.CoreV1().RESTClient()
	listWatch := cache.NewListWatchFromClient(restClient, "namespaces", "", fields.Everything())
	nr.k8sNamespaceStore, nr.k8sNamespaceController = cache.NewInformer(
		listWatch,
		&clientapi_v1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ns, ok := obj.(*clientapi_v1.Namespace)
				if !ok {
					nr.Log.Warn("Failed to cast newly created namespace object")
				} else {
					nr.addNamespace(ns)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ns, ok := obj.(*clientapi_v1.Namespace)
				if !ok {
					nr.Log.Warn("Failed to cast removed namespace object")
				} else {
					nr.deleteNamespace(ns)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				nsOld, ok1 := oldObj.(*clientapi_v1.Namespace)
				nsNew, ok2 := newObj.(*clientapi_v1.Namespace)
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

func (nr *NamespaceReflector) Start() {
	nr.wg.Add(1)
	go nr.run()
}

func (nr *NamespaceReflector) addNamespace(ns *clientapi_v1.Namespace) {
	nr.Log.WithField("ns", ns).Info("Namespace added")
	nsProto := nr.namespaceToProto(ns)
	key := proto.NamespaceKey(ns.GetName())
	err := nr.Publish.Put(key, nsProto)
	if err != nil {
		nr.Log.WithField("err", err).Warn("Failed to add namespace state data into the data store")
	}
}

func (nr *NamespaceReflector) deleteNamespace(ns *clientapi_v1.Namespace) {
	nr.Log.WithField("ns", ns).Info("Namespace removed")
	// TODO (Delete not yet supported by kvdbsync)
	//key := proto.NamespaceKey(ns.GetName())
	//err := nr.Publish.Delete(key)
	//if err != nil {
	//	nr.Log.WithField("err", err).Warn("Failed to remove namespace state data from the data store")
	//}
}

func (nr *NamespaceReflector) updateNamespace(nsNew, nsOld *clientapi_v1.Namespace) {
	nr.Log.WithFields(map[string]interface{}{"ns-old": nsOld, "ns-new": nsNew}).Info("Namespace updated")
	nsProto := nr.namespaceToProto(nsNew)
	key := proto.NamespaceKey(nsNew.GetName())
	err := nr.Publish.Put(key, nsProto)
	if err != nil {
		nr.Log.WithField("err", err).Warn("Failed to update namespace state data in the data store")
	}
}

func (nr *NamespaceReflector) run() {
	defer nr.wg.Done()

	nr.Log.Info("Namespace reflector is now running")
	nr.k8sNamespaceController.Run(nr.stopCh)
	nr.Log.Info("Stopping Namespace reflector")
}

func (nr *NamespaceReflector) namespaceToProto(ns *clientapi_v1.Namespace) *proto.Namespace {
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

func (nr *NamespaceReflector) Close() error {
	return nil
}
