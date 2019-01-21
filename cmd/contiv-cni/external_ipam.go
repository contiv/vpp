package main

import (
	"encoding/json"
	"fmt"

	cnisb "github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ipam"
	nodemodel "github.com/contiv/vpp/plugins/ksr/model/node"
	"github.com/ligato/cn-infra/db/keyval"
	"github.com/ligato/cn-infra/db/keyval/etcd"
	"github.com/ligato/cn-infra/db/keyval/kvproto"
	"github.com/ligato/cn-infra/logging"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

const (
	agentPrefix = "/vnf-agent/"

	hostLocalPluginName = "host-local"
)

func execIPAMAdd(plugin string, netconf []byte) (string, error) {
	log.Debugf("Calling external IPAM: %s", plugin)

	if plugin == hostLocalPluginName {
		// special case: need to convert usePodCidr to actual POD CIDR for this node
		netconf = replacePodCIDR(netconf)
	}

	// execute the IPAM plugin
	r, err := ipam.ExecAdd(plugin, netconf)
	if err != nil {
		return "", err
	}

	// convert and store the cniResult
	ipamResult, err := cnisb.NewResultFromResult(r)
	if err != nil {
		return "", fmt.Errorf("cannot convert IPAM result: %v", err)
	}

	log.Debugf("IPAM plugin %s ADD cniResult: %v", plugin, ipamResult)

	if len(ipamResult.IPs) > 0 {
		json, err := ipamResult.IPs[0].MarshalJSON()
		if err != nil {
			return "", fmt.Errorf("cannot marshall IPAM result: %v", err)
		}
		return string(json[:]), nil
	}
	return "", nil
}

func execIPAMDel(plugin string, netconf []byte) error {
	log.Debugf("Calling external IPAM: %s", plugin)

	if plugin == hostLocalPluginName {
		// special case: need to convert usePodCidr to actual POD CIDR for this node
		netconf = replacePodCIDR(netconf)
	}

	err := ipam.ExecDel(plugin, netconf)
	if err != nil {
		return fmt.Errorf("IPAM plugin %s: DEL returned an error: %v", plugin, err)
	}

	log.Debugf("IPAM plugin %s DEL OK", plugin)
	return nil
}

func replacePodCIDR(netconf []byte) []byte {

	// unmarshall netconf data
	var cniConfig map[string]interface{}
	if err := json.Unmarshal(netconf, &cniConfig); err != nil {
		log.Errorf("Error by unmarshalling CNI config: %v", err)
		return netconf
	}

	ipamData, ok := cniConfig["ipam"].(map[string]interface{})
	if !ok {
		fmt.Printf("failed to parse host-local IPAM data; was expecting a dict, not: %v", cniConfig["ipam"])
	}

	// replace usePodCidr in subnet with an actual subnet
	subnet, _ := ipamData["subnet"].(string)
	if strings.EqualFold(subnet, "usePodCidr") {
		ipamData["subnet"] = getPodCIDR()
	}

	// marshall netconf data back
	result, err := json.Marshal(cniConfig)
	if err != nil {
		log.Errorf("Error by marshalling CNI config: %v", err)
		return netconf
	}

	log.Debugf("modified netconf: %s", string(result))

	return result
}

func getPodCIDR() string {
	_, broker, err := createEtcdClient()
	if err != nil {
		log.Errorf("Error by creating ETCD client: %v", err)
		return ""
	}

	hostName, err := os.Hostname()

	key := fmt.Sprintf("%s/%s", "contiv-ksr/k8s/node", hostName)

	nodeInfo := &nodemodel.Node{}
	found, _, err := broker.GetValue(key, nodeInfo)
	if err != nil {
		log.Errorf("Error by getting ETCD value: %v", err)
		return ""
	}

	if !found {
		log.Errorf("ETCD key %s not found: %s", key)
		return ""
	}

	return nodeInfo.Pod_CIDR
}

func createEtcdClient() (*etcd.BytesConnectionEtcd, keyval.ProtoBroker, error) {

	cfg := &etcd.Config{
		Endpoints:         []string{"http://127.0.0.1:12379"},
		InsecureTransport: true,
		DialTimeout:       10000000000,
	}
	//if err := config.ParseConfigFromYamlFile(configFile, cfg); err != nil {
	//	return nil, nil, err
	//}

	etcdConfig, err := etcd.ConfigToClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	bDB, err := etcd.NewEtcdConnectionWithBytes(*etcdConfig, logging.DefaultLogger)
	if err != nil {
		return nil, nil, err
	}

	return bDB, kvproto.NewProtoWrapperWithSerializer(bDB, &keyval.SerializerJSON{}).NewBroker(agentPrefix), nil
}
