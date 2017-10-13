package policy

import (
	"time"

	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/logging"

	"github.com/ligato/vpp-agent/clientv1/defaultplugins/localclient"
	"github.com/ligato/vpp-agent/plugins/defaultplugins/aclplugin/model/acl"

	"github.com/contiv/vpp/plugins/contiv"
	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/policy"
)

// ConfigProcessor processes K8s config changes into VPP ACL changes.
type ConfigProcessor struct {
	ProcessorDeps

	// internal fields...
	//  - memory storage for policies, namespaces, pods (consider using cn-infra/idxmap)
}

// ProcessorDeps defines dependencies of the K8s Config processor.
type ProcessorDeps struct {
	Log        logging.Logger
	PluginName core.PluginName
	Contiv     *contiv.Plugin /* for GetIfName() */
	// This is how you get the name of the VPP interface attached into the pod:
	// ifName, meta, found := pp.Contiv.GetIfName(pod.Namespace, pod.Name)

	// TODO: inject PolicyReflector(s)
}

// Init initializes Config Processor.
func (pp *ConfigProcessor) Init() error {
	return nil
}

// Resync processes an initial state of K8s config.
func (pp *ConfigProcessor) Resync(event *DataResyncEvent) error {
	pp.Log.WithField("event", event).Info("RESYNC of K8s configuration BEGIN")
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		pp.Log.WithField("durationInNs", duration.Nanoseconds()).Info("RESYNC of K8s configuration END")
	}()

	// TODO: Process entire K8s config and create all ACLs from scratch.
	//  - but we will do simple scenarios first
	acl1 := &acl.AccessLists_Acl{}
	acl2 := &acl.AccessLists_Acl{}
	acl3 := &acl.AccessLists_Acl{}
	err := localclient.DataResyncRequest(pp.PluginName).
		ACL(acl1).
		ACL(acl2).
		ACL(acl3).
		Send().ReceiveReply()
	return err
}

// AddPolicy stores k8s policy locally, gets the PodSelector label and does a lookup for all
// pods with the same label. Then applies policy to the Pods.
func (pp *ConfigProcessor) AddPolicy(policy *policy.Policy) error {
	pp.Log.WithField("policy", policy).Info("Add Policy")

	// TODO
	acl := &acl.AccessLists_Acl{}
	err := localclient.DataChangeRequest(pp.PluginName).
		Put().
		ACL(acl).
		Send().ReceiveReply()
	return err
}

// DelPolicy deletes local data of a removed K8s policy and removes ACL configuration
// from Pod interfaces in VPP.
func (pp *ConfigProcessor) DelPolicy(policy *policy.Policy) error {
	pp.Log.WithField("policy", policy).Info("Delete Policy")
	// TODO
	return nil
}

// UpdatePolicy updates local data of the updated K8s policy and updates ACL configuration
// to Pod interfaces in VPP.
func (pp *ConfigProcessor) UpdatePolicy(oldPolicy, newPolicy *policy.Policy) error {
	pp.Log.WithFields(logging.Fields{"old": oldPolicy, "new": newPolicy}).Info("Update Policy")
	// TODO
	return nil
}

// AddPod ...
func (pp *ConfigProcessor) AddPod(pod *pod.Pod) error {
	pp.Log.WithField("pod", pod).Info("Add Pod")
	// TODO

	return nil
}

// DelPod ...
func (pp *ConfigProcessor) DelPod(pod *pod.Pod) error {
	pp.Log.WithField("pod", pod).Info("Delete Pod")
	// TODO
	return nil
}

// UpdatePod ...
func (pp *ConfigProcessor) UpdatePod(oldPod, newPod *pod.Pod) error {
	pp.Log.WithFields(logging.Fields{"old": oldPod, "new": newPod}).Info("Update Pod")
	// TODO
	return nil
}

// AddNamespace ...
func (pp *ConfigProcessor) AddNamespace(ns *namespace.Namespace) error {
	pp.Log.WithField("namespace", ns).Info("Add Namespace")
	// TODO
	return nil
}

// DelNamespace ...
func (pp *ConfigProcessor) DelNamespace(ns *namespace.Namespace) error {
	pp.Log.WithField("namespace", ns).Info("Delete Namespace")
	// TODO
	return nil
}

// UpdateNamespace ...
func (pp *ConfigProcessor) UpdateNamespace(oldNs, newNs *namespace.Namespace) error {
	pp.Log.WithFields(logging.Fields{"old": oldNs, "new": newNs}).Info("Update Namespace")
	// TODO
	return nil
}

// Close frees resources allocated by Config Processor.
func (pp *ConfigProcessor) Close() error {
	return nil
}
