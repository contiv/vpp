package processor

import (
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/servicelabel"

	nsmodel "github.com/contiv/vpp/plugins/ksr/model/namespace"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	policymodel "github.com/contiv/vpp/plugins/ksr/model/policy"

	"github.com/contiv/vpp/plugins/policy/cache"
	config "github.com/contiv/vpp/plugins/policy/configurator"
)

// PolicyProcessor processes K8s State data and generates list of Contiv
// policies for each pod with outdated configuration.
// PolicyProcessor implements the PolicyCacheWatcher interface to watch
// for changes and RESYNC events via the Policy Cache. For each change,
// it decides if the re-configuration is ready to go or it needs to be postponed
// until more data are available. If the change carries enough information,
// the processor first determines the list of pods with outdated policy config
// and then for each of them re-calculates the list of Contiv policies
// that should be configured. Request for re-configuration is propagated into
// the layer below - the Policy Configurator.
type PolicyProcessor struct {
	ProcessorDeps
}

type ProcessorDeps struct {
	Log          logging.Logger
	ServiceLabel servicelabel.ReaderAPI /* microservice used to determine Host IP */
	Cache        cache.PolicyCacheAPI
	Configurator config.PolicyConfiguratorAPI
}

func (pp *PolicyProcessor) Init() error {
	return nil
}

// Process re-calculates the list of Contiv policies for pods with outdated
// configuration.
func (pp *PolicyProcessor) Process(resync bool, pods []podmodel.ID) error {
	txn := pp.Configurator.NewTxn(false)
	for _, pod := range pods {
		policies := []*config.ContivPolicy{}
		// TODO: get and pre-process policies currently assigned to the pod
		// optimization: remember already evaluated policies between iterations
		txn.Configure(pod, policies)
	}
	return txn.Commit()
}

func (pp *PolicyProcessor) Resync(data *cache.K8sStateResyncData) error {
	return pp.Process(true, pp.Cache.ListAllPods())
}

func (pp *PolicyProcessor) AddPod(pod *podmodel.Pod) error {
	pods := []podmodel.ID{podmodel.GetID(pod)}
	// TODO: consider postponing the re-configuration until more data are available (e.g. pod ip address)
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) DelPod(pod *podmodel.Pod) error {
	pods := []podmodel.ID{podmodel.GetID(pod)}
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) UpdatePod(oldPod, newPod *podmodel.Pod) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	//       - here we probably need to consider changed/added/removed port alias
	//       - also handle migration of pods across hosts
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) AddPolicy(policy *policymodel.Policy) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	// TODO: consider postponing the re-configuration until more data are available
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) DelPolicy(policy *policymodel.Policy) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) UpdatePolicy(oldPolicy, newPolicy *policymodel.Policy) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) AddNamespace(ns *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	// TODO: consider postponing the re-configuration until more data are available
	//         - e.g. empty namespace has no effect
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) DelNamespace(ns *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) UpdateNamespace(oldNs, newNs *nsmodel.Namespace) error {
	pods := []podmodel.ID{}
	// TODO: determine the list of pods with outdated policy configuration
	return pp.Process(false, pods)
}

func (pp *PolicyProcessor) Close() error {
	return nil
}
