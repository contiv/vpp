package configurator

import (
	"net"
	"sort"

	"github.com/ligato/cn-infra/logging"

	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/cache"
	"github.com/contiv/vpp/plugins/policy/renderer"
)

// PolicyConfigurator translates a set of Contiv Policies into ingress and
// egress lists of Contiv Rules (n-tuples with the most basic policy rule
// definition) and applies them into the target vswitch via registered
// renderers. Allows to register multiple renderers for different network stacks.
// For the best performance, creates a shortest possible sequence of rules
// that implement a given policy. Furthermore, to allow renderers share a list
// of ingress or egress rules between interfaces, the same set of policies
// always results in the same list of rules.
type PolicyConfigurator struct {
	Deps

	renderers         []renderer.PolicyRendererAPI
	parallelRendering bool
}

// Deps lists dependencies of PolicyConfigurator.
type Deps struct {
	Log   logging.Logger
	Cache cache.PolicyCacheAPI
}

// PolicyConfiguratorTxn represents a single transaction of the policy configurator.
type PolicyConfiguratorTxn struct {
	Log          logging.Logger
	configurator *PolicyConfigurator
	resync       bool
	config       map[podmodel.ID]ContivPolicies // config to render
}

// ContivPolicies is a list of policies that can be ordered by policy ID.
type ContivPolicies []*ContivPolicy

// ProcessedPolicySet stores configuration already generated for a given
// set of policies. It is used only temporarily for a duration of the commit
// for a performance optimization.
type ProcessedPolicySet struct {
	policies ContivPolicies // ordered
	ingress  ContivRules
	egress   ContivRules
}

// ContivRules is a list of Contiv rules.
type ContivRules []*renderer.ContivRule

// Init initializes policy configurator.
func (pc *PolicyConfigurator) Init(parallelRendering bool) error {
	pc.renderers = []renderer.PolicyRendererAPI{}
	pc.parallelRendering = parallelRendering
	return nil
}

// RegisterRenderer registers a new renderer.
// The renderer will be receiving rules for all pods in this K8s node.
// It is up to the render to possibly filter out rules for pods without
// an inter-connection in the destination network stack.
func (pc *PolicyConfigurator) RegisterRenderer(renderer renderer.PolicyRendererAPI) error {
	pc.renderers = append(pc.renderers, renderer)
	return nil
}

// Close deallocates resource held by the configurator.
func (pc *PolicyConfigurator) Close() error {
	return nil
}

// NewTxn starts a new transaction. The re-configuration executes only after
// Commit() is called. If <resync> is enabled, the supplied configuration will
// completely replace the existing one, otherwise pods not mentioned in the
// transaction are left unchanged.
func (pc *PolicyConfigurator) NewTxn(resync bool) Txn {
	txn := &PolicyConfiguratorTxn{
		Log:          pc.Log,
		configurator: pc,
		resync:       resync,
		config:       make(map[podmodel.ID]ContivPolicies),
	}
	return txn
}

// Configure applies the set of policies for a given pod. The existing policies
// are replaced. The order of policies is not important (it is a set).
func (pct *PolicyConfiguratorTxn) Configure(pod podmodel.ID, policies []*ContivPolicy) Txn {
	pct.Log.WithFields(logging.Fields{
		"pod":      pod,
		"policies": policies,
	}).Debug("PolicyConfigurator Configure()")
	pct.config[pod] = policies
	return pct
}

// Commit proceeds with the reconfiguration.
func (pct *PolicyConfiguratorTxn) Commit() error {
	// Remember processed sets of policies between iterations so that the same
	// set will not be processed more than once.
	processed := []ProcessedPolicySet{}

	// Transactions of all registered renderers.
	rendererTxns := []renderer.Txn{}

	for pod, unorderedPolicies := range pct.config {
		var ingress ContivRules
		var egress ContivRules

		// Get target pod configuration.
		found, podData := pct.configurator.Cache.LookupPod(pod)
		if !found {
			pct.Log.WithField("pod", pod).Warn("Pod data not found in the cache")
			continue
		}

		// Get pod IP address (expressed as one-host subnet).
		if podData.IpAddress == "" {
			pct.Log.WithField("pod", pod).Warn("Pod has no IP address assigned")
			continue
		}
		podIPNet := getOneHostSubnet(podData.IpAddress)
		if podIPNet == nil {
			pct.Log.WithField("pod", pod).Warn("Pod has invalid IP address assigned")
			continue
		}

		// Sort policies to get the same outcome for the same set.
		policies := unorderedPolicies.Copy()
		sort.Sort(policies)

		// Check if this set was already processed.
		alreadyProcessed := false
		for _, policySet := range processed {
			if policySet.policies.Equals(policies) {
				ingress = policySet.ingress
				egress = policySet.egress
				alreadyProcessed = true
			}
		}

		// Generate rules for a set of policies not yet processed.
		if !alreadyProcessed {
			// Direction in policies is from the pod point of view, whereas rules
			// are evaluated from the vswitch perspective.
			egress = pct.generateRules(MatchIngress, policies)
			ingress = pct.generateRules(MatchEgress, policies)
		}

		// Start transaction on every renderer if they are not running already.
		if len(rendererTxns) == 0 {
			for _, renderer := range pct.configurator.renderers {
				rendererTxns = append(rendererTxns, renderer.NewTxn(pct.resync))
			}
		}

		// Add rules into the transactions.
		for _, rTxn := range rendererTxns {
			rTxn.Render(pod, podIPNet, ingress.Copy(), egress.Copy())
		}

		// Remember already processed set of policies.
		if !alreadyProcessed {
			processed = append(processed,
				ProcessedPolicySet{
					policies: policies,
					ingress:  ingress,
					egress:   egress,
				})
		}
	}

	// Commit all renderer transactions.
	rndrChan := make(chan error)
	for _, rTxn := range rendererTxns {
		if pct.configurator.parallelRendering {
			go func(txn renderer.Txn) {
				err := txn.Commit()
				rndrChan <- err
			}(rTxn)
		} else {
			err := rTxn.Commit()
			if err != nil {
				return err
			}
		}
	}
	if pct.configurator.parallelRendering {
		var wasError error
		for i := 0; i < len(rendererTxns); i++ {
			err := <-rndrChan
			if err != nil {
				wasError = err
			}
		}
		if wasError != nil {
			return wasError
		}
	}

	return nil
}

// PeerPod represents the opposite pod in the policy rule.
type PeerPod struct {
	ID    podmodel.ID
	IPNet *net.IPNet
}

// Generate a list of ingress or egress rules implementing a given list of policies.
func (pct *PolicyConfiguratorTxn) generateRules(direction MatchType, policies ContivPolicies) ContivRules {
	rules := ContivRules{}
	hasPolicy := false

	for _, policy := range policies {
		if (policy.Type == PolicyIngress && direction == MatchEgress) ||
			(policy.Type == PolicyEgress && direction == MatchIngress) {
			// Policy does not apply to this direction.
			continue
		}
		hasPolicy = true

		for _, match := range policy.Matches {
			if match.Type != direction {
				continue
			}

			// Collect IP addresses of all pod peers.
			peers := []PeerPod{}
			for _, peer := range match.Pods {
				found, peerData := pct.configurator.Cache.LookupPod(peer)
				if !found {
					pct.Log.WithField("peer", peer).Warn("Peer pod data not found in the cache")
					continue
				}
				if peerData.IpAddress == "" {
					pct.Log.WithField("peer", peer).Warn("Peer pod has no IP address assigned")
					continue
				}
				peerIPNet := getOneHostSubnet(peerData.IpAddress)
				if peerIPNet == nil {
					pct.Log.WithFields(logging.Fields{
						"peer": peer,
						"ip":   peerData.IpAddress}).Warn("Peer pod has invalid IP address assigned")
					continue
				}
				peers = append(peers, PeerPod{ID: peer, IPNet: peerIPNet})
			}

			// Collect all subnets from IPBlocks.
			allSubnets := []*net.IPNet{}
			for _, block := range match.IPBlocks {
				subnets := []*net.IPNet{&block.Network}
				for _, except := range block.Except {
					subtracted := []*net.IPNet{}
					for _, subnet := range subnets {
						subtracted = append(subtracted, subtractSubnet(subnet, &except)...)
					}
					subnets = subtracted
				}
				allSubnets = append(allSubnets, subnets...)
			}

			// Handle empty set of pods and IP blocks.
			// = match anything on L3
			if len(peers) == 0 && len(allSubnets) == 0 {
				if len(match.Ports) == 0 {
					// = match anything on L3 & L4
					ruleTCPAny := &renderer.ContivRule{
						ID:          policy.ID.String() + "-TCP:ANY",
						Action:      renderer.ActionPermit,
						SrcNetwork:  &net.IPNet{},
						DestNetwork: &net.IPNet{},
						Protocol:    renderer.TCP,
						SrcPort:     0,
						DestPort:    0,
					}
					ruleUDPAny := &renderer.ContivRule{
						ID:          policy.ID.String() + "-UDP:ANY",
						Action:      renderer.ActionPermit,
						SrcNetwork:  &net.IPNet{},
						DestNetwork: &net.IPNet{},
						Protocol:    renderer.UDP,
						SrcPort:     0,
						DestPort:    0,
					}
					rules = pct.appendRules(rules, ruleTCPAny, ruleUDPAny)
				} else {
					// = match by L4
					for _, port := range match.Ports {
						rule := &renderer.ContivRule{
							ID:          policy.ID.String() + "-" + port.String(),
							Action:      renderer.ActionPermit,
							SrcNetwork:  &net.IPNet{},
							DestNetwork: &net.IPNet{},
							SrcPort:     0,
							DestPort:    port.Number,
						}
						if port.Protocol == TCP {
							rule.Protocol = renderer.TCP
						} else {
							rule.Protocol = renderer.UDP
						}
						rules = pct.appendRules(rules, rule)
					}
				}
			}

			// Combine pod peers with ports.
			for _, peer := range peers {
				if len(match.Ports) == 0 {
					// Match all ports.
					// = match by L3
					ruleTCPAny := &renderer.ContivRule{
						ID:          policy.ID.String() + "-" + peer.ID.String() + "-TCP:ANY",
						Action:      renderer.ActionPermit,
						Protocol:    renderer.TCP,
						SrcNetwork:  &net.IPNet{},
						DestNetwork: &net.IPNet{},
						SrcPort:     0,
						DestPort:    0,
					}
					ruleUDPAny := &renderer.ContivRule{
						ID:          policy.ID.String() + "-" + peer.ID.String() + "-UDP:ANY",
						Action:      renderer.ActionPermit,
						Protocol:    renderer.UDP,
						SrcNetwork:  &net.IPNet{},
						DestNetwork: &net.IPNet{},
						SrcPort:     0,
						DestPort:    0,
					}
					if direction == MatchIngress {
						ruleTCPAny.SrcNetwork = peer.IPNet
						ruleUDPAny.SrcNetwork = peer.IPNet
					} else {
						ruleTCPAny.DestNetwork = peer.IPNet
						ruleUDPAny.DestNetwork = peer.IPNet
					}
					rules = pct.appendRules(rules, ruleTCPAny, ruleUDPAny)
				} else {
					// Combine each port with the peer.
					// = match by L3 & L4
					for _, port := range match.Ports {
						rule := &renderer.ContivRule{
							ID:          policy.ID.String() + "-" + peer.ID.String() + "-" + port.String(),
							Action:      renderer.ActionPermit,
							SrcNetwork:  &net.IPNet{},
							DestNetwork: &net.IPNet{},
							SrcPort:     0,
							DestPort:    port.Number,
						}
						if direction == MatchIngress {
							rule.SrcNetwork = peer.IPNet
						} else {
							rule.DestNetwork = peer.IPNet
						}
						if port.Protocol == TCP {
							rule.Protocol = renderer.TCP
						} else {
							rule.Protocol = renderer.UDP
						}
						rules = pct.appendRules(rules, rule)
					}
				}
			}

			// Combine IPBlocks with ports.
			for _, subnet := range allSubnets {
				if len(match.Ports) == 0 {
					// Handle IPBlock with no ports.
					// = match by L3
					ruleTCPAny := &renderer.ContivRule{
						ID:          policy.ID.String() + "-" + subnet.String() + "-TCP:ANY",
						Action:      renderer.ActionPermit,
						Protocol:    renderer.TCP,
						SrcNetwork:  &net.IPNet{},
						DestNetwork: &net.IPNet{},
						SrcPort:     0,
						DestPort:    0,
					}
					ruleUDPAny := &renderer.ContivRule{
						ID:          policy.ID.String() + "-" + subnet.String() + "-UDP:ANY",
						Action:      renderer.ActionPermit,
						Protocol:    renderer.UDP,
						SrcNetwork:  &net.IPNet{},
						DestNetwork: &net.IPNet{},
						SrcPort:     0,
						DestPort:    0,
					}
					if direction == MatchIngress {
						ruleTCPAny.SrcNetwork = subnet
						ruleUDPAny.SrcNetwork = subnet
					} else {
						ruleTCPAny.DestNetwork = subnet
						ruleUDPAny.DestNetwork = subnet
					}
					rules = pct.appendRules(rules, ruleTCPAny, ruleUDPAny)
				} else {
					// Combine each port with the block.
					// = match by L3 & L4
					for _, port := range match.Ports {
						rule := &renderer.ContivRule{
							ID:          policy.ID.String() + "-" + subnet.String() + "-" + port.String(),
							Action:      renderer.ActionPermit,
							SrcNetwork:  &net.IPNet{},
							DestNetwork: &net.IPNet{},
							SrcPort:     0,
							DestPort:    port.Number,
						}
						if direction == MatchIngress {
							rule.SrcNetwork = subnet
						} else {
							rule.DestNetwork = subnet
						}
						if port.Protocol == TCP {
							rule.Protocol = renderer.TCP
						} else {
							rule.Protocol = renderer.UDP
						}
						rules = pct.appendRules(rules, rule)
					}
				}
			}
		}
	}

	if hasPolicy {
		// Deny the rest.
		ruleTCPNone := &renderer.ContivRule{
			ID:          "TCP:NONE",
			Action:      renderer.ActionDeny,
			SrcNetwork:  &net.IPNet{},
			DestNetwork: &net.IPNet{},
			Protocol:    renderer.TCP,
			SrcPort:     0,
			DestPort:    0,
		}
		ruleUDPNone := &renderer.ContivRule{
			ID:          "UDP:NONE",
			Action:      renderer.ActionDeny,
			SrcNetwork:  &net.IPNet{},
			DestNetwork: &net.IPNet{},
			Protocol:    renderer.UDP,
			SrcPort:     0,
			DestPort:    0,
		}
		rules = pct.appendRules(rules, ruleTCPNone, ruleUDPNone)
	}

	return rules
}

// Append rule into the list if it is not there already.
func (pct *PolicyConfiguratorTxn) appendRule(rules []*renderer.ContivRule, newRule *renderer.ContivRule) []*renderer.ContivRule {
	for _, rule := range rules {
		if rule.ID == newRule.ID {
			pct.Log.WithField("rule", newRule).Debug("Skipping duplicate rule")
			return rules
		}
	}
	return append(rules, newRule)
}

// Append rules into the list. Skip those which are already there.
func (pct *PolicyConfiguratorTxn) appendRules(rules []*renderer.ContivRule, newRules ...*renderer.ContivRule) []*renderer.ContivRule {
	for _, newRule := range newRules {
		rules = pct.appendRule(rules, newRule)
	}
	return rules
}

// Copy creates a shallow copy of ContivPolicies.
func (cp ContivPolicies) Copy() ContivPolicies {
	cpCopy := make(ContivPolicies, len(cp))
	copy(cpCopy, cp)
	return cpCopy
}

// Equals returns true for equal lists of policies.
func (cp ContivPolicies) Equals(cp2 ContivPolicies) bool {
	if len(cp) != len(cp2) {
		return false
	}
	for idx, policy := range cp {
		if policy.ID != cp2[idx].ID {
			return false
		}
	}
	return true
}

// Len return the number of policies in the list.
func (cp ContivPolicies) Len() int {
	return len(cp)
}

// Swap replaces order of two policies in the list.
func (cp ContivPolicies) Swap(i, j int) {
	cp[i], cp[j] = cp[j], cp[i]
}

// Less compares two policies by their IDs.
func (cp ContivPolicies) Less(i, j int) bool {
	if cp[i].ID.Namespace < cp[j].ID.Namespace {
		return true
	}
	if cp[i].ID.Namespace == cp[j].ID.Namespace {
		if cp[i].ID.Name < cp[j].ID.Name {
			return true
		}
	}
	return false
}

// Copy creates a deep copy of ContivRules.
func (cr ContivRules) Copy() ContivRules {
	crCopy := make(ContivRules, len(cr))
	for idx, rule := range cr {
		crCopy[idx] = &renderer.ContivRule{}
		*(crCopy[idx]) = *rule
	}
	return crCopy
}

// compareInts is a comparison function for two integers.
func compareInts(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// Function returns the IP subnet that contains only the given host
// (i.e. /32 for IPv4, /128 for IPv6).
func getOneHostSubnet(hostAddr string) *net.IPNet {
	ip := net.ParseIP(hostAddr)
	if ip == nil {
		return nil
	}
	ipNet := &net.IPNet{IP: ip}
	if ip.To4() != nil {
		ipNet.Mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)
	} else {
		ipNet.Mask = net.CIDRMask(net.IPv6len*8, net.IPv6len*8)
	}
	return ipNet
}

// Function returns a list of subnets with all IPs included in net1 and not included in net2.
func subtractSubnet(net1, net2 *net.IPNet) []*net.IPNet {
	result := []*net.IPNet{}
	net1MaskSize, _ := net1.Mask.Size()
	net2MaskSize, _ := net2.Mask.Size()
	if net1MaskSize > net2MaskSize {
		// net2 higher than net1 in the tree
		if !net2.Contains(net1.IP) {
			result = append(result, net1)
		}
	} else if net1MaskSize == net2MaskSize {
		// same level in the tree
		if !net1.IP.Equal(net2.IP) {
			result = append(result, net1)
		}
	} else {
		// net2 lower then net1 in the tree
		if !net1.Contains(net2.IP) {
			result = append(result, net1)
		} else {
			// net2 under net1
			for bit := net1MaskSize; bit < net2MaskSize; bit++ {
				subnet := &net.IPNet{}
				subnet.Mask = net.CIDRMask(bit+1, len(net2.Mask)*8)
				subnet.IP = net2.IP.Mask(subnet.Mask)
				// flip the last bit of the IP
				subnet.IP[bit/8] ^= byte(1 << uint(7-(bit%8)))
				result = append(result, subnet)
			}
		}
	}

	return result
}
