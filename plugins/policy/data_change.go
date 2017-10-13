package policy

import (
	"strings"

	"github.com/ligato/cn-infra/datasync"

	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/policy"
)

// changePropagateEvent propagates CHANGE in the K8s configuration into the Policy Processor.
func (p *Plugin) changePropagateEvent(dataChngEv datasync.ChangeEvent) error {
	var err error
	var diff bool
	key := dataChngEv.GetKey()
	p.Log.Debug("Received CHANGE key ", key)

	if strings.HasPrefix(key, namespace.KeyPrefix()) {
		// Propagate Policy CHANGE event
		_, _, err = policy.ParsePolicyFromKey(key)
		if err == nil {
			var value, prevValue policy.Policy
			if err = dataChngEv.GetValue(&value); err != nil {
				return err
			}
			if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
				return err
			}
			if datasync.Delete == dataChngEv.GetChangeType() {
				return p.policyProcessor.DelPolicy(&prevValue)
			} else if diff {
				return p.policyProcessor.UpdatePolicy(&prevValue, &value)
			}
			return p.policyProcessor.AddPolicy(&value)
		}

		// Propagate Pod CHANGE event
		_, _, err = pod.ParsePodFromKey(key)
		if err == nil {
			var value, prevValue pod.Pod
			if err = dataChngEv.GetValue(&value); err != nil {
				return err
			}
			if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
				return err
			}
			if datasync.Delete == dataChngEv.GetChangeType() {
				return p.policyProcessor.DelPod(&prevValue)
			} else if diff {
				return p.policyProcessor.UpdatePod(&prevValue, &value)
			}
			return p.policyProcessor.AddPod(&value)
		}

		// Propagate Namespace CHANGE event
		var value, prevValue namespace.Namespace
		if err = dataChngEv.GetValue(&value); err != nil {
			return err
		}
		if diff, err = dataChngEv.GetPrevValue(&prevValue); err != nil {
			return err
		}
		if datasync.Delete == dataChngEv.GetChangeType() {
			return p.policyProcessor.DelNamespace(&prevValue)
		} else if diff {
			return p.policyProcessor.UpdateNamespace(&prevValue, &value)
		}
		return p.policyProcessor.AddNamespace(&value)
	} else {
		p.Log.WithField("event", dataChngEv).Warn("Ignoring CHANGE event")
	}
	return nil
}
