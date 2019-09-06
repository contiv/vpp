// Copyright (c) 2019 Bell Canada, Pantheon Technologies and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package srv6

import (
	"fmt"
	"net"
	"strings"

	linux_interfaces "github.com/ligato/vpp-agent/api/models/linux/interfaces"

	"github.com/contiv/vpp/plugins/contivconf"
	controller "github.com/contiv/vpp/plugins/controller/api"
	"github.com/contiv/vpp/plugins/ipam"
	"github.com/contiv/vpp/plugins/ipnet"
	"github.com/contiv/vpp/plugins/sfc/config"
	"github.com/contiv/vpp/plugins/sfc/renderer"
	"github.com/contiv/vpp/plugins/statscollector"
	"github.com/ligato/cn-infra/logging"
	vpp_l3 "github.com/ligato/vpp-agent/api/models/vpp/l3"
	vpp_srv6 "github.com/ligato/vpp-agent/api/models/vpp/srv6"
	"github.com/ligato/vpp-agent/pkg/models"
	"github.com/pkg/errors"
)

const (
	ipv6PodSidPrefix = "/128"
	ipv6AddrAny      = "::"
)

// Renderer implements SRv6 - SRv6 rendering of SFC in Contiv-VPP.
type Renderer struct {
	Deps
}

// Deps lists dependencies of the Renderer.
type Deps struct {
	Log              logging.Logger
	Config           *config.Config
	ContivConf       contivconf.API
	IPAM             ipam.API
	IPNet            ipnet.API
	ConfigRetriever  controller.ConfigRetriever
	UpdateTxnFactory func(change string) (txn controller.UpdateOperations)
	ResyncTxnFactory func() (txn controller.ResyncOperations)
	Stats            statscollector.API /* used for exporting the statistics */
}

// Init initializes the renderer.
func (rndr *Renderer) Init() error {
	if rndr.Config == nil {
		rndr.Config = config.DefaultConfig()
	}
	return nil
}

// AfterInit does nothing for this renderer.
func (rndr *Renderer) AfterInit() error {
	return nil
}

// AddChain is called for a newly added service function chain.
func (rndr *Renderer) AddChain(sfc *renderer.ContivSFC) error {
	rndr.Log.Infof("Add SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("add SFC '%s'", sfc.Name))

	config, err := rndr.renderChain(sfc)
	if err != nil {
		return errors.Wrapf(err, "can't add chain %v", sfc)
	}
	controller.PutAll(txn, config)

	return nil
}

// UpdateChain informs renderer about a change in the configuration or in the state of a service function chain.
func (rndr *Renderer) UpdateChain(oldSFC, newSFC *renderer.ContivSFC) error {
	rndr.Log.Infof("Update SFC: %v", newSFC)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("update SFC '%s'", newSFC.Name))

	oldConfig, err := rndr.renderChain(oldSFC)
	if err != nil {
		return errors.Wrapf(err, "can't remove old chain %v", oldSFC)
	}
	newConfig, err := rndr.renderChain(newSFC)
	if err != nil {
		return errors.Wrapf(err, "can't add new chain %v", newSFC)
	}

	controller.DeleteAll(txn, oldConfig)
	controller.PutAll(txn, newConfig)

	return nil
}

// DeleteChain is called for every removed service function chain.
func (rndr *Renderer) DeleteChain(sfc *renderer.ContivSFC) error {
	rndr.Log.Infof("Delete SFC: %v", sfc)

	txn := rndr.UpdateTxnFactory(fmt.Sprintf("delete SFC chain '%s'", sfc.Name))

	config, err := rndr.renderChain(sfc)
	if err != nil {
		return errors.Wrapf(err, "can't delete chain %v", sfc)
	}
	controller.DeleteAll(txn, config)

	return nil
}

// Resync completely replaces the current configuration with the provided full state of service chains.
func (rndr *Renderer) Resync(resyncEv *renderer.ResyncEventData) error {
	txn := rndr.ResyncTxnFactory()

	// resync SFC configuration
	for _, sfc := range resyncEv.Chains {
		config, err := rndr.renderChain(sfc)
		if err != nil {
			return errors.Wrapf(err, "can't resync chain %v", sfc)
		}
		controller.PutAll(txn, config)
	}

	return nil
}

// Close deallocates resources held by the renderer.
func (rndr *Renderer) Close() error {
	return nil
}

// locations for packet that is travelling SFC chain
const (
	remoteLocation int = iota
	podVRFLocation
	mainVRFLocation
)

const (
	l2DX2Endpoint int = iota
	l3Dx4Endpoint
	l3Dx6Endpoint
)

func (rndr *Renderer) getEndLinkCustomIfIPNet(sfc *renderer.ContivSFC) (endLinkCustomIfIPNet *net.IPNet) {
	endLinkPod := sfc.Chain[len(sfc.Chain)-1].Pods[0]
	return rndr.IPAM.GetPodCustomIfIP(endLinkPod.ID, endLinkPod.InputInterfaceConfigName, sfc.Network)
}

// isIPv6 returns true if the IP address is an IPv6 address, false otherwise.
func isIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return strings.Contains(ip.String(), ":")
}

func (rndr *Renderer) endPointType(sfc *renderer.ContivSFC) int {
	// if end pond IP address is nil, then we use l2endpoint
	endIPNet := rndr.getEndLinkCustomIfIPNet(sfc)
	if endIPNet == nil {
		return l2DX2Endpoint
	}

	if isIPv6(endIPNet.IP) {
		return l3Dx6Endpoint
	}

	return l3Dx4Endpoint
}

// renderChain renders Contiv SFC to VPP configuration.
func (rndr *Renderer) renderChain(sfc *renderer.ContivSFC) (config controller.KeyValuePairs, err error) {
	// TODO support external interfaces across whole renderer
	// TODO remove all debug logging later
	rndr.Log.Debugf("[DEBUG]sfc: %v", sfc)

	// SFC configuration correctness checks
	config = make(controller.KeyValuePairs)
	if sfc == nil {
		return config, errors.New("can't create sfc chain configuration due to missing sfc information")
	}
	if sfc.Chain == nil || len(sfc.Chain) == 0 {
		return config, errors.New("can't create sfc chain configuration due to missing chain information")
	}
	if len(sfc.Chain) < 2 {
		return config, errors.New("can't create sfc chain configuration due to missing information on start and end chain links (chain has less than 2 links)")
	}
	if len(sfc.Chain) == 2 {
		rndr.Log.Warnf("sfc chain %v doesn't have inner links, it has only start and end links", sfc.Name)
	}

	// creating steering and policy (we will install SRv6 components in the same order as packet will go through SFC chain)
	packetLocation := remoteLocation // tracking packet location to create correct configuration that enables correct packet routing
	localStartPods := rndr.localPods(sfc.Chain[0])
	if len(localStartPods) > 0 { // no local start pods = no steering to SFC (-> also no policy)
		bsid := rndr.IPAM.BsidForSFCPolicy(sfc.Name)
		rndr.createSteerings(localStartPods, sfc, bsid, config)
		if err := rndr.createPolicy(sfc, bsid, localStartPods[0].NodeID, config); err != nil {
			return config, errors.Wrapf(err, "can't create SRv6 policy for SFC chain with name %v", sfc.Name)
		}
		packetLocation = mainVRFLocation
	}

	// create inner links and end link
	for i, link := range sfc.Chain[1:len(sfc.Chain)] {
		pod := link.Pods[0] // TODO support multiple pods in inner/end chain link (multiple loadbalance routes or something...)
		if pod.Local {
			podIPNet := rndr.IPAM.GetPodIP(pod.ID)
			if podIPNet == nil || podIPNet.IP == nil {
				return config, errors.Errorf("excluding link %s from SFC chain(localsid creation) because there is no IP address for pod %s", link.String(), pod.ID.String())
			}
			if i == len(sfc.Chain)-2 { // end link
				if packetLocation == mainVRFLocation || packetLocation == remoteLocation { // remote packet will arrive in mainVRF -> packet is in mainVRF
					rndr.createRouteToPodVrf(rndr.IPAM.SidForSFCEndLocalsid(podIPNet.IP.To16()), config)
					packetLocation = podVRFLocation
				}
				if err := rndr.createEndLinkLocalsid(sfc, podIPNet.IP.To16(), config, pod); err != nil {
					return config, errors.Wrapf(err, "can't create end link local sid (pod %v) for sfc chain %v", pod.ID, sfc.Name)
				}
			} else { // inner link
				if packetLocation == mainVRFLocation || packetLocation == remoteLocation { // remote packet will arrive in mainVRF -> packet is in mainVRF
					rndr.createRouteToPodVrf(rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, podIPNet.IP.To16()), config)
					packetLocation = podVRFLocation
				}
				if err := rndr.createInnerLinkLocalsids(sfc, pod, podIPNet.IP.To16(), config); err != nil {
					return config, errors.Wrapf(err, "can't create inner link local sid (pod %v) for sfc chain %v", pod.ID, sfc.Name)
				}
				if rndr.endPointType(sfc) == l2DX2Endpoint { // l2DX2Endpoint -> L2 SR-unware service
					packetLocation = mainVRFLocation // proxy leaving packets check main table instead of pod vrf table (maybe that check table service output interface and that is stub so default table 0)
				}
			}
		} else {
			if packetLocation == podVRFLocation {
				otherNodeIP, _, err := rndr.IPAM.NodeIPAddress(pod.NodeID)
				if err != nil {
					return config, errors.Wrapf(err, "cant create route from pod VRF to main VRF to achieve route "+
						"between local and remote sibling SFC links due to unability to generate node IP address from pod ID  %v", pod.NodeID)
				}
				rndr.createRouteToMainVrf(rndr.IPAM.SidForServiceNodeLocalsid(otherNodeIP), config) // TODO rename SidForServiceNodeLocalsid and related config stuff to reflect usage in SFC
			}
			// NOTE: further routing to intermediate Localsid (Localsid that ends segment that only transports packet to another node) is configured in ipnet package
			// -> no need to add routing out of node here
			packetLocation = remoteLocation
		}
	}

	return config, nil
}

func (rndr *Renderer) createInnerLinkLocalsids(sfc *renderer.ContivSFC, pod *renderer.PodSF, servicePodIP net.IP, config controller.KeyValuePairs) error {
	localSID := &vpp_srv6.LocalSID{
		Sid:               rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, servicePodIP).String(),
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
	}

	switch rndr.endPointType(sfc) {
	case l2DX2Endpoint:
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_AD{EndFunction_AD: &vpp_srv6.LocalSID_EndAD{ // L2 service
			OutgoingInterface: pod.InputInterface,  // outgoing interface for SR-proxy is input interface for service
			IncomingInterface: pod.OutputInterface, // incoming interface for SR-proxy is output interface for service
		}}
	case l3Dx4Endpoint:
		fallthrough
	case l3Dx6Endpoint:
		podOutputIfIPNet := rndr.IPAM.GetPodCustomIfIP(pod.ID, pod.OutputInterfaceConfigName, sfc.Network)
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_AD{EndFunction_AD: &vpp_srv6.LocalSID_EndAD{ // L3 service
			L3ServiceAddress:  podOutputIfIPNet.IP.String(),
			OutgoingInterface: pod.InputInterface,  // outgoing interface for SR-proxy is input interface for service
			IncomingInterface: pod.OutputInterface, // incoming interface for SR-proxy is output interface for service
		}}

		if err := rndr.setARPForPodInputInterface(podOutputIfIPNet, config, pod); err != nil {
			return errors.Wrapf(err, "can't set arp for service pod %v", pod.ID)
		}
	}
	config[models.Key(localSID)] = localSID
	return nil
}

func (rndr *Renderer) setARPForPodInputInterface(podIPNet *net.IPNet, config controller.KeyValuePairs, pod *renderer.PodSF) error {
	macAddress, err := rndr.podCustomIFPhysAddress(pod, pod.InputInterfaceConfigName)
	if err != nil {
		return errors.Wrapf(err, "can't retrieve physical(mac) address for custom interface %v on pod %v of sfc chain", pod.InputInterfaceConfigName, pod.ID)
	}
	arpTable := &vpp_l3.ARPEntry{
		Interface:   pod.InputInterface,
		IpAddress:   podIPNet.IP.String(),
		PhysAddress: macAddress,
	}

	config[models.Key(arpTable)] = arpTable
	return nil
}

func (rndr *Renderer) podCustomIFPhysAddress(pod *renderer.PodSF, customIFName string) (string, error) {
	_, linuxIfName, exists := rndr.IPNet.GetPodCustomIfNames(pod.ID.Namespace, pod.ID.Name, customIFName)
	if !exists {
		return "", errors.Errorf("Unable to get logical name of custom interface for pod %v", pod.ID)
	}
	val := rndr.ConfigRetriever.GetConfig(linux_interfaces.InterfaceKey(linuxIfName))
	if val == nil {
		return "", errors.Errorf("Unable to get data for custom interface for pod %v", pod.ID)
	}
	linuxInterface, ok := val.(*linux_interfaces.Interface)
	if !ok {
		return "", errors.Errorf("Retrieved data for custom interface for pod %v have bad type (%+v)", pod.ID, val)
	}
	return linuxInterface.PhysAddress, nil
}

func (rndr *Renderer) createEndLinkLocalsid(sfc *renderer.ContivSFC, endLinkAddress net.IP, config controller.KeyValuePairs, pod *renderer.PodSF) error {
	localSID := &vpp_srv6.LocalSID{
		Sid:               rndr.IPAM.SidForSFCEndLocalsid(endLinkAddress).String(),
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
	}

	switch rndr.endPointType(sfc) {
	case l2DX2Endpoint:
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DX2{
			EndFunction_DX2: &vpp_srv6.LocalSID_EndDX2{
				OutgoingInterface: pod.InputInterface,
			},
		}
	case l3Dx4Endpoint:
		endIPNet := rndr.getEndLinkCustomIfIPNet(sfc)
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DX4{
			EndFunction_DX4: &vpp_srv6.LocalSID_EndDX4{
				NextHop:           endIPNet.IP.String(),
				OutgoingInterface: pod.InputInterface,
			},
		}
		if err := rndr.setARPForPodInputInterface(endIPNet, config, pod); err != nil {
			return errors.Wrapf(err, "can't set arp for end pod %v", pod.ID)
		}
	case l3Dx6Endpoint:
		endIPNet := rndr.getEndLinkCustomIfIPNet(sfc)
		localSID.EndFunction = &vpp_srv6.LocalSID_EndFunction_DX6{
			EndFunction_DX6: &vpp_srv6.LocalSID_EndDX6{
				NextHop:           endIPNet.IP.String(),
				OutgoingInterface: pod.InputInterface,
			},
		}
		if err := rndr.setARPForPodInputInterface(endIPNet, config, pod); err != nil {
			return errors.Wrapf(err, "can't set arp for end pod %v", pod.ID)
		}
	}

	config[models.Key(localSID)] = localSID
	return nil
}

func (rndr *Renderer) createRouteToPodVrf(steeredIP net.IP, config controller.KeyValuePairs) {
	rndr.createRouteBetweenVrfTables(rndr.ContivConf.GetRoutingConfig().MainVRFID, rndr.ContivConf.GetRoutingConfig().PodVRFID, steeredIP, config)
}

func (rndr *Renderer) createRouteToMainVrf(steeredIP net.IP, config controller.KeyValuePairs) {
	rndr.createRouteBetweenVrfTables(rndr.ContivConf.GetRoutingConfig().PodVRFID, rndr.ContivConf.GetRoutingConfig().MainVRFID, steeredIP, config)
}

func (rndr *Renderer) createRouteBetweenVrfTables(fromVrf, toVrf uint32, steeredIP net.IP, config controller.KeyValuePairs) {
	route := &vpp_l3.Route{
		Type:        vpp_l3.Route_INTER_VRF,
		DstNetwork:  steeredIP.String() + ipv6PodSidPrefix,
		VrfId:       fromVrf,
		ViaVrfId:    toVrf,
		NextHopAddr: ipv6AddrAny,
	}

	config[models.Key(route)] = route
}

func (rndr *Renderer) createPolicy(sfc *renderer.ContivSFC, bsid net.IP, thisNodeID uint32, config controller.KeyValuePairs) error {
	// create Srv6 policy with segment list for each backend (loadbalancing and packet switching part)
	// First podIP represent start (steering) function to SRv6
	// Last podIP represent end function to SRv6
	segments := make([]string, 0)
	lastSegmentNode := thisNodeID

	// add segments for inner links of chain
	for i, link := range sfc.Chain[1:len(sfc.Chain)] {
		pod := link.Pods[0] // TODO support multiple pods in inner/end chain link (multiple loadbalance routes or something...)
		podIPNet := rndr.IPAM.GetPodIP(pod.ID)
		if podIPNet == nil || podIPNet.IP == nil {
			return errors.Errorf("excluding link %s from SFC chain(policy creation) because there is no IP address for pod %s", link.String(), pod.ID.String())
		}
		if lastSegmentNode != pod.NodeID { // move to another node
			nodeIP, _, err := rndr.IPAM.NodeIPAddress(pod.NodeID)
			if err != nil {
				return errors.Wrapf(err, "unable to create node-to-node transportation segment due to failure in generatation of node IP address for node id  %v", pod.NodeID)
			}
			segments = append(segments, rndr.IPAM.SidForServiceNodeLocalsid(nodeIP.To16()).String())
			lastSegmentNode = pod.NodeID
		}
		if i == len(sfc.Chain)-2 { // end link
			segments = append(segments, rndr.IPAM.SidForSFCEndLocalsid(podIPNet.IP.To16()).String())
		} else { // inner link
			segments = append(segments, rndr.IPAM.SidForSFCServiceFunctionLocalsid(sfc.Name, podIPNet.IP.To16()).String())
		}
	}

	// combine sergments to segment lists
	segmentLists := make([]*vpp_srv6.Policy_SegmentList, 0)
	segmentLists = append(segmentLists,
		&vpp_srv6.Policy_SegmentList{
			Weight:   1,
			Segments: segments,
		})

	// create policy
	policy := &vpp_srv6.Policy{
		InstallationVrfId: rndr.ContivConf.GetRoutingConfig().MainVRFID,
		Bsid:              bsid.String(),
		SegmentLists:      segmentLists,
		SprayBehaviour:    false, // loadbalance packets and not duplicate(spray) it to all segment lists
		SrhEncapsulation:  true,
	}
	config[models.Key(policy)] = policy
	return nil
}

func (rndr *Renderer) createSteerings(localStartPods []*renderer.PodSF, sfc *renderer.ContivSFC, bsid net.IP, config controller.KeyValuePairs) {
	switch rndr.endPointType(sfc) {
	case l2DX2Endpoint:
		for _, startPod := range localStartPods {
			steering := &vpp_srv6.Steering{
				Name: fmt.Sprintf("forK8sSFC-%s-from-pod-%s", sfc.Name, startPod.ID.String()),
				PolicyRef: &vpp_srv6.Steering_PolicyBsid{
					PolicyBsid: bsid.String(),
				},
				Traffic: &vpp_srv6.Steering_L2Traffic_{
					L2Traffic: &vpp_srv6.Steering_L2Traffic{
						InterfaceName: startPod.OutputInterface,
					},
				},
			}
			rndr.Log.Debugf("[DEBUG] l2 steering: %v", steering)
			config[models.Key(steering)] = steering
		}
	case l3Dx6Endpoint, l3Dx4Endpoint:
		endIPNet := rndr.getEndLinkCustomIfIPNet(sfc)
		steering := &vpp_srv6.Steering{
			Name: fmt.Sprintf("forK8sSFC-%s", sfc.Name),
			PolicyRef: &vpp_srv6.Steering_PolicyBsid{
				PolicyBsid: bsid.String(),
			},
			Traffic: &vpp_srv6.Steering_L3Traffic_{
				L3Traffic: &vpp_srv6.Steering_L3Traffic{
					InstallationVrfId: rndr.ContivConf.GetRoutingConfig().PodVRFID,
					PrefixAddress:     endIPNet.String(),
				},
			},
		}
		config[models.Key(steering)] = steering
	}
}

func (rndr *Renderer) localPods(sf *renderer.ServiceFunction) []*renderer.PodSF {
	localPods := make([]*renderer.PodSF, 0)
	for _, pod := range sf.Pods {
		if pod.Local {
			localPods = append(localPods, pod)
		}
	}
	return localPods
}
