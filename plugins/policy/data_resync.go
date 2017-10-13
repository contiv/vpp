package policy

import (
	"strings"

	"github.com/ligato/cn-infra/datasync"
	"github.com/ligato/cn-infra/logging"

	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/policy"
)

type DataResyncEvent struct {
	Namespaces []*namespace.Namespace
	Pods       []*pod.Pod
	Policies   []*policy.Policy
}

func NewDataResyncEvent() *DataResyncEvent {
	return &DataResyncEvent{
		Namespaces: []*namespace.Namespace{},
		Pods:       []*pod.Pod{},
		Policies:   []*policy.Policy{},
	}
}

// resyncParseEvent parses K8s configuration RESYNC event for use by the Policy Processor.
func (p *Plugin) resyncParseEvent(resyncEv datasync.ResyncEvent) *DataResyncEvent {
	var numNs int
	var numPolicy int
	var numPod int

	event := NewDataResyncEvent()
	for key := range resyncEv.GetValues() {
		p.Log.Debug("Received RESYNC key ", key)
	}
	for key, resyncData := range resyncEv.GetValues() {
		if strings.HasPrefix(key, namespace.KeyPrefix()) {
			for {
				evData, stop := resyncData.GetNext()
				if stop {
					break
				}
				key := evData.GetKey()

				// Parse policy RESYNC event
				_, _, err := policy.ParsePolicyFromKey(key)
				if err == nil {
					value := &policy.Policy{}
					err := evData.GetValue(value)
					if err == nil {
						event.Policies = append(event.Policies, value)
						numPolicy++
					}
					continue
				}

				// Parse pod RESYNC event
				_, _, err = pod.ParsePodFromKey(key)
				if err == nil {
					value := &pod.Pod{}
					err := evData.GetValue(value)
					if err == nil {
						event.Pods = append(event.Pods, value)
						numPod++
					}
					continue
				}

				// Parse namespace RESYNC event
				value := &namespace.Namespace{}
				err = evData.GetValue(value)
				if err == nil {
					event.Namespaces = append(event.Namespaces, value)
					numNs++
				}
			}
			p.Log.WithFields(logging.Fields{
				"num-policies": numPolicy,
				"num-pods":     numPod,
				"num-ns":       numNs,
			}).Debug("Parsed RESYNC event")
		} else {
			p.Log.WithField("event", resyncEv).Warn("Ignoring RESYNC event")
		}
	}
	return event
}
