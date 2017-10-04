package reflector

import (
	"sync"

	"k8s.io/apimachinery/pkg/fields"
	clientapi_v1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"

	proto "github.com/contiv/vpp/plugins/reflector/model/pod"
)

type PodReflector struct {
	ReflectorDeps

	stopCh <-chan struct{}
	wg     *sync.WaitGroup

	k8sPodStore      cache.Store
	k8sPodController cache.Controller
}

func (pr *PodReflector) Init(stopCh2 <-chan struct{}, wg *sync.WaitGroup) error {
	pr.stopCh = stopCh2
	pr.wg = wg

	restClient := pr.K8sClientset.CoreV1().RESTClient()
	listWatch := cache.NewListWatchFromClient(restClient, "pods", "", fields.Everything())
	pr.k8sPodStore, pr.k8sPodController = cache.NewInformer(
		listWatch,
		&clientapi_v1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod, ok := obj.(*clientapi_v1.Pod)
				if !ok {
					pr.Log.Warn("Failed to cast newly created pod object")
				} else {
					pr.addPod(pod)
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod, ok := obj.(*clientapi_v1.Pod)
				if !ok {
					pr.Log.Warn("Failed to cast removed pod object")
				} else {
					pr.deletePod(pod)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				podOld, ok1 := oldObj.(*clientapi_v1.Pod)
				podNew, ok2 := newObj.(*clientapi_v1.Pod)
				if !ok1 || !ok2 {
					pr.Log.Warn("Failed to cast changed pod object")
				} else {
					pr.updatePod(podNew, podOld)
				}
			},
		},
	)
	return nil
}

func (pr *PodReflector) Start() {
	pr.wg.Add(1)
	go pr.run()
}

func (pr *PodReflector) addPod(pod *clientapi_v1.Pod) {
	pr.Log.WithField("pod", pod).Info("Pod added")
	podProto := pr.podToProto(pod)
	key := proto.PodKey(pod.GetName(), pod.GetNamespace())
	err := pr.Publish.Put(key, podProto)
	if err != nil {
		pr.Log.WithField("err", err).Warn("Failed to add pod state data into the data store")
	}
}

func (pr *PodReflector) deletePod(pod *clientapi_v1.Pod) {
	pr.Log.WithField("pod", pod).Info("Pod removed")
	// TODO (Delete not yet supported by kvdbsync)
	//key := proto.PodKey(pod.GetName(), pod.GetNamespace())
	//err := pr.Publish.Delete(key)
	//if err != nil {
	//	pr.Log.WithField("err", err).Warn("Failed to remove pod state data from the data store")
	//}
}

func (pr *PodReflector) updatePod(podNew, podOld *clientapi_v1.Pod) {
	pr.Log.WithFields(map[string]interface{}{"pod-old": podOld, "pod-new": podNew}).Info("Pod updated")
	podProto := pr.podToProto(podNew)
	key := proto.PodKey(podNew.GetName(), podNew.GetNamespace())
	err := pr.Publish.Put(key, podProto)
	if err != nil {
		pr.Log.WithField("err", err).Warn("Failed to update pod state data in the data store")
	}
}

func (pr *PodReflector) run() {
	defer pr.wg.Done()

	pr.Log.Info("Pod reflector is now running")
	pr.k8sPodController.Run(pr.stopCh)
	pr.Log.Info("Stopping Pod reflector")
}

func (pr *PodReflector) podToProto(pod *clientapi_v1.Pod) *proto.Pod {
	podProto := &proto.Pod{}
	podProto.Name = pod.GetName()
	podProto.Namespace = pod.GetNamespace()
	labels := pod.GetLabels()
	if labels != nil {
		for key, val := range labels {
			podProto.Label = append(podProto.Label, &proto.Pod_Label{Key: key, Value: val})

		}
	}
	podProto.IpAddress = pod.Status.PodIP
	for _, container := range pod.Spec.Containers {
		podProto.Container = append(podProto.Container, pr.containerToProto(&container))
	}

	return podProto
}

func (pr *PodReflector) containerToProto(container *clientapi_v1.Container) *proto.Pod_Container {
	containerProto := &proto.Pod_Container{}
	containerProto.Name = container.Name
	for _, port := range container.Ports {
		portProto := &proto.Pod_Container_Port{}
		portProto.Name = port.Name
		portProto.HostPort = port.HostPort
		portProto.ContainerPort = port.ContainerPort
		switch port.Protocol {
		case clientapi_v1.ProtocolTCP:
			portProto.Protocol = proto.Pod_Container_Port_TCP
		case clientapi_v1.ProtocolUDP:
			portProto.Protocol = proto.Pod_Container_Port_UDP
		}
		portProto.HostIpAddress = port.HostIP
		containerProto.Port = append(containerProto.Port, portProto)
	}
	return containerProto
}

func (pr *PodReflector) Close() error {
	return nil
}
