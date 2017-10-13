package policy

import (
	"strings"

	"github.com/ligato/cn-infra/datasync"

	"github.com/contiv/vpp/plugins/ksr/model/namespace"
	"github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/ksr/model/policy"
)

// changePropagateEvent propagates CHANGE in the K8s configuration into the Config Processor.
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
				return p.configProcessor.DelPolicy(&prevValue)
			} else if diff {
				return p.configProcessor.UpdatePolicy(&prevValue, &value)
			}
			return p.configProcessor.AddPolicy(&value)
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
				return p.configProcessor.DelPod(&prevValue)
			} else if diff {
				return p.configProcessor.UpdatePod(&prevValue, &value)
			}
			return p.configProcessor.AddPod(&value)
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
			return p.configProcessor.DelNamespace(&prevValue)
		} else if diff {
			return p.configProcessor.UpdateNamespace(&prevValue, &value)
		}
		return p.configProcessor.AddNamespace(&value)
	}

	p.Log.WithField("event", dataChngEv).Warn("Ignoring CHANGE event")
	return nil
}
