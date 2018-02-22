/*
 * // Copyright (c) 2018 Cisco and/or its affiliates.
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at:
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package aclengine

import (
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/ligato/cn-infra/logging"

	"fmt"
	"github.com/contiv/vpp/mock/localclient"
	"github.com/contiv/vpp/plugins/contiv"
	podmodel "github.com/contiv/vpp/plugins/ksr/model/pod"
	"github.com/contiv/vpp/plugins/policy/renderer"
	vpp_acl "github.com/ligato/vpp-agent/plugins/defaultplugins/common/model/acl"
)

const maxPortNum = uint32(^uint16(0))

// ConnectionAction is one of DENY-SYN, DENY-SYN-ACK, ALLOW, FAILURE.
type ConnectionAction int

const (
	// ConnActionDenySyn is returned by the mock ACL engine when the SYN packet is blocked.
	ConnActionDenySyn ConnectionAction = iota

	// ConnActionDenySynAck is returned by the mock ACL engine when the SYN-ACK packet is blocked.
	ConnActionDenySynAck

	// ConnActionAllow is returned by the mock ACL engine when the connection is allowed.
	ConnActionAllow

	// ConnActionFailure is returned by the mock ACL engine when TestConnection() fails.
	ConnActionFailure
)

// ACLAction is one of DENY, PERMIT, REFLECT, FAILURE.
type ACLAction int

const (
	// ACLActionDeny is returned by evalACL when the packet is blocked by ACL.
	ACLActionDeny ACLAction = iota

	// ACLActionPermit is returned by evalACL when the packet is allowed by ACL.
	ACLActionPermit

	// ACLActionReflect is returned by evalACL when the packet is allowed+reflected by ACL.
	ACLActionReflect

	// ACLActionFailure is returned by evalACL when it fails.
	ACLActionFailure
)

// MockACLEngine simulates ACL evaluation engine from the VPP/ACL plugin.
type MockACLEngine struct {
	sync.Mutex

	Log    logging.Logger
	Contiv contiv.API /* for GetIfName(), GetMainPhysicalIfName(), GetVxlanBVIIfName() */

	pods      map[podmodel.ID]*PodConfig
	aclConfig *ACLConfig
}

// PodConfig encapsulates pod configuration.
type PodConfig struct {
	podIP       *net.IPNet
	anotherNode bool
}

// ACLConfig stores currently installed ACLs.
type ACLConfig struct {
	byName map[string]*vpp_acl.AccessLists_Acl
	byIf   map[string]*InterfaceACLs
}

// InterfaceACLs stores ACLs assigned to interface.
type InterfaceACLs struct {
	inbound  *vpp_acl.AccessLists_Acl
	outbound *vpp_acl.AccessLists_Acl
}

// NewMockACLEngine is a constructor for MockACLEngine.
func NewMockACLEngine(log logging.Logger, contiv contiv.API) *MockACLEngine {
	return &MockACLEngine{
		Log:       log,
		Contiv:    contiv,
		pods:      make(map[podmodel.ID]*PodConfig),
		aclConfig: NewACLConfig(),
	}
}

// NewACLConfig is a constructor for ACLConfig.
func NewACLConfig() *ACLConfig {
	return &ACLConfig{
		byName: make(map[string]*vpp_acl.AccessLists_Acl),
		byIf:   make(map[string]*InterfaceACLs),
	}
}

// RegisterPod registers a deployed pod.
// Set *anotherNode* to true if the pod was deployed on another node.
// TestConnection assumes no ACLs installed on other nodes.
func (mae *MockACLEngine) RegisterPod(pod podmodel.ID, podIP *net.IPNet, anotherNode bool) {
	mae.Lock()
	defer mae.Unlock()
	mae.pods[pod] = &PodConfig{podIP: podIP, anotherNode: anotherNode}
}

// ApplyTxn applies transaction created by ACL renderer.
func (mae *MockACLEngine) ApplyTxn(txn *localclient.Txn) error {
	mae.Lock()
	defer mae.Unlock()

	if txn == nil {
		return errors.New("txn is nil")
	}

	if txn.DefaultPluginsDataChangeTxn != nil || txn.DefaultPluginsDataResyncTxn != nil {
		return errors.New("defaultplugins txn is not supported")
	}

	if txn.LinuxDataResyncTxn != nil {
		return errors.New("linux resync txn is not supported")
	}

	if txn.LinuxDataChangeTxn == nil {
		return errors.New("linux data change txn is nil")
	}

	dataChange := txn.LinuxDataChangeTxn
	for _, op := range dataChange.Ops {
		if !strings.HasPrefix(op.Key, vpp_acl.KeyPrefix()) {
			return errors.New("non-ACL changed in txn")
		}
		aclName := strings.TrimPrefix(op.Key, vpp_acl.KeyPrefix())
		if op.Value != nil {
			// put ACL
			acl, isACL := op.Value.(*vpp_acl.AccessLists_Acl)
			if !isACL {
				return errors.New("failed to cast ACL value")
			}
			err := mae.aclConfig.PutACL(acl)
			if err != nil {
				return err
			}
		} else {
			// remove ACL
			err := mae.aclConfig.DelACL(aclName)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// DumpACLs returns all ACLs currently installed.
func (mae *MockACLEngine) DumpACLs() (acls []*vpp_acl.AccessLists_Acl) {
	for _, acl := range mae.aclConfig.byName {
		acls = append(acls, acl)
	}
	return acls
}

// TestConnection allows to simulate a connection establishment and tests what
// the outcome in terms of ACLs would be.
func (mae *MockACLEngine) TestConnection(srcPod podmodel.ID, dstPod podmodel.ID,
	protocol renderer.ProtocolType, srcPort, dstPort uint16) ConnectionAction {

	mae.Lock()
	defer mae.Unlock()

	var srcIfName, dstIfName string
	var srcIfReflected, dstIfReflected bool

	// Get configuration for both pods.
	srcPodCfg, hasCfg := mae.pods[srcPod]
	if !hasCfg {
		return ConnActionFailure
	}
	dstPodCfg, hasCfg := mae.pods[dstPod]
	if !hasCfg {
		return ConnActionFailure
	}

	// Get source interface.
	if srcPodCfg.anotherNode {
		srcIfName = mae.Contiv.GetVxlanBVIIfName()
		if srcIfName == "" {
			srcIfName = mae.Contiv.GetMainPhysicalIfName()
		}
		if srcIfName == "" {
			return ConnActionFailure
		}
	} else {
		var exists bool
		srcIfName, exists = mae.Contiv.GetIfName(srcPod.Namespace, srcPod.Name)
		if !exists {
			return ConnActionFailure
		}
	}

	// Get destination interface.
	if dstPodCfg.anotherNode {
		dstIfName = mae.Contiv.GetVxlanBVIIfName()
		if dstIfName == "" {
			dstIfName = mae.Contiv.GetMainPhysicalIfName()
		}
		if dstIfName == "" {
			return ConnActionFailure
		}
	} else {
		var exists bool
		dstIfName, exists = mae.Contiv.GetIfName(dstPod.Namespace, dstPod.Name)
		if !exists {
			return ConnActionFailure
		}
	}

	// Get ACLs on the communication path.
	srcACLs := mae.aclConfig.GetACLs(srcIfName)
	dstACLs := mae.aclConfig.GetACLs(dstIfName)

	// SYN packet:
	//   -> test inbound ACL for source interface
	srcInAction := mae.evalACL(srcACLs.inbound, srcPodCfg.podIP.IP, dstPodCfg.podIP.IP,
		protocol, dstPort)
	if srcInAction == ACLActionFailure {
		return ConnActionFailure
	}
	if srcInAction == ACLActionDeny {
		return ConnActionDenySyn
	}
	if srcInAction == ACLActionReflect {
		srcIfReflected = true
	}
	//   -> test outbound ACL for destination interface
	dstOutAction := mae.evalACL(dstACLs.outbound, srcPodCfg.podIP.IP, dstPodCfg.podIP.IP,
		protocol, dstPort)
	if dstOutAction == ACLActionFailure {
		return ConnActionFailure
	}
	if dstOutAction == ACLActionDeny {
		return ConnActionDenySyn
	}
	if dstOutAction == ACLActionReflect {
		dstIfReflected = true
	}

	// SYN-ACK packet:
	//   -> test inbound ACL for destination interface
	if !dstIfReflected {
		dstInAction := mae.evalACL(dstACLs.inbound, dstPodCfg.podIP.IP, srcPodCfg.podIP.IP,
			protocol, srcPort)
		if dstInAction == ACLActionFailure {
			return ConnActionFailure
		}
		if dstInAction == ACLActionDeny {
			return ConnActionDenySynAck
		}
	}
	//   -> test outbound ACL for source interface
	if !srcIfReflected {
		srcOutAction := mae.evalACL(srcACLs.outbound, dstPodCfg.podIP.IP, srcPodCfg.podIP.IP,
			protocol, srcPort)
		if srcOutAction == ACLActionFailure {
			return ConnActionFailure
		}
		if srcOutAction == ACLActionDeny {
			return ConnActionDenySynAck
		}
	}

	return ConnActionAllow
}

func (mae *MockACLEngine) evalACL(acl *vpp_acl.AccessLists_Acl, srcIP, dstIP net.IP,
	protocol renderer.ProtocolType, dstPort uint16) ACLAction {

	if acl == nil {
		return ACLActionPermit
	}

	for _, rule := range acl.Rules {
		if rule.Matches.MacipRule != nil {
			// unsupported
			return ACLActionFailure
		}
		if rule.Matches.IpRule == nil {
			// invalid
			return ACLActionFailure
		}
		ipRule := rule.Matches.IpRule
		if ipRule.Icmp != nil || ipRule.Other != nil || ipRule.Ip == nil {
			// unsupported
			return ACLActionFailure
		}

		// check source network
		if ipRule.Ip.SourceNetwork != "" {
			_, srcNetwork, err := net.ParseCIDR(ipRule.Ip.SourceNetwork)
			if err != nil {
				// invalid
				return ACLActionFailure
			}
			if !srcNetwork.Contains(srcIP) {
				// not matching
				continue
			}
		}

		// check destination network
		if ipRule.Ip.DestinationNetwork != "" {
			_, dstNetwork, err := net.ParseCIDR(ipRule.Ip.DestinationNetwork)
			if err != nil {
				// invalid
				return ACLActionFailure
			}
			if !dstNetwork.Contains(dstIP) {
				// not matching
				continue
			}
		}

		// check L4
		if protocol == renderer.TCP {
			if ipRule.Tcp == nil || ipRule.Udp != nil {
				// invalid
				return ACLActionFailure
			}

			// check source port range (should be ALL-PORTS)
			srcPortRange := ipRule.Tcp.SourcePortRange
			if srcPortRange == nil {
				// invalid
				return ACLActionFailure
			}
			if srcPortRange.LowerPort != 0 || srcPortRange.UpperPort != maxPortNum {
				// invalid
				return ACLActionFailure
			}

			// check destination port range
			dstPortRange := ipRule.Tcp.DestinationPortRange
			if dstPortRange == nil {
				// invalid
				return ACLActionFailure
			}
			if dstPort < uint16(dstPortRange.LowerPort) || dstPort > uint16(dstPortRange.UpperPort) {
				// not matching
				continue
			}

		} else {
			if ipRule.Udp == nil || ipRule.Tcp != nil {
				// invalid
				return ACLActionFailure
			}

			// check source port range (should be ALL-PORTS)
			srcPortRange := ipRule.Udp.SourcePortRange
			if srcPortRange == nil {
				// invalid
				return ACLActionFailure
			}
			if srcPortRange.LowerPort != 0 || srcPortRange.UpperPort != maxPortNum {
				// invalid
				return ACLActionFailure
			}

			// check destination port range
			dstPortRange := ipRule.Udp.DestinationPortRange
			if dstPortRange == nil {
				// invalid
				return ACLActionFailure
			}
			if dstPort < uint16(dstPortRange.LowerPort) || dstPort > uint16(dstPortRange.UpperPort) {
				// not matching
				continue
			}
		}

		// Rule matches the packet!
		if rule.Actions == nil {
			// invalid
			return ACLActionFailure
		}
		switch rule.Actions.AclAction {
		case vpp_acl.AclAction_DENY:
			return ACLActionDeny
		case vpp_acl.AclAction_PERMIT:
			return ACLActionPermit
		case vpp_acl.AclAction_REFLECT:
			return ACLActionReflect
		default:
			return ACLActionFailure
		}
	}

	return ACLActionDeny /* deny is the default action */
}

// GetACLs returns ACLs assigned to the given interface.
func (ac *ACLConfig) GetACLs(ifName string) *InterfaceACLs {
	acls, hasACL := ac.byIf[ifName]
	if !hasACL {
		return &InterfaceACLs{}
	}
	return acls
}

// DelACL removes ACL with the given name.
func (ac *ACLConfig) DelACL(aclName string) error {
	_, hasACL := ac.byName[aclName]
	if !hasACL {
		return fmt.Errorf("cannot find ACL: %s", aclName)
	}
	delete(ac.byName, aclName)
	for _, aclCfg := range ac.byIf {
		if aclCfg.inbound != nil && aclCfg.inbound.AclName == aclName {
			aclCfg.inbound = nil
		}
		if aclCfg.outbound != nil && aclCfg.outbound.AclName == aclName {
			aclCfg.outbound = nil
		}
	}
	return nil
}

// PutACL adds the given ACL.
func (ac *ACLConfig) PutACL(acl *vpp_acl.AccessLists_Acl) error {
	if acl == nil {
		return errors.New("ACL is nil")
	}
	if acl.Interfaces == nil ||
		(len(acl.Interfaces.Ingress) == 0 && len(acl.Interfaces.Egress) == 0) {
		return errors.New("ACL with empty interfaces")
	}
	_, hasACL := ac.byName[acl.AclName]
	if hasACL {
		// del origin ACL first
		ac.DelACL(acl.AclName)
	}
	ac.byName[acl.AclName] = acl
	for _, ifName := range acl.Interfaces.Ingress {
		if _, hasACLCfg := ac.byIf[ifName]; !hasACLCfg {
			ac.byIf[ifName] = &InterfaceACLs{}
		}
		ac.byIf[ifName].inbound = acl
	}
	for _, ifName := range acl.Interfaces.Egress {
		if _, hasACLCfg := ac.byIf[ifName]; !hasACLCfg {
			ac.byIf[ifName] = &InterfaceACLs{}
		}
		ac.byIf[ifName].outbound = acl
	}
	return nil
}
