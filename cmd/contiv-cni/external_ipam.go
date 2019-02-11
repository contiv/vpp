package main

import (
	"encoding/json"
	"fmt"

	"errors"
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
	// name of the host-local plugin
	hostLocalPluginName = "host-local"

	// keys in the IPAM config
	cfgIpamKey   = "ipam"
	cfgSubnetKey = "subnet"

	// special keword that needs to be replaced with the actual host POD CIDR address
	podCidrSubstKey = "usePodCidr"

	// ETCD prefixes
	etcdAgentPrefix = "/vnf-agent/"
	etcdNodePrefix  = "contiv-ksr/k8s/node"
)

func execIPAMAdd(cfg *cniConfig, netconf []byte) (string, error) {
	log.Debugf("Calling external IPAM: %s", cfg.IPAM.Type)

	if cfg.IPAM.Type == hostLocalPluginName {
		// special case: need to convert usePodCidr to actual POD CIDR for this node
		netconf = replacePodCIDR(netconf, cfg.EtcdEndpoints)
	}

	// execute the IPAM plugin
	r, err := ipam.ExecAdd(cfg.IPAM.Type, netconf)
	if err != nil {
		return "", err
	}

	// convert and store the cniResult
	ipamResult, err := cnisb.NewResultFromResult(r)
	if err != nil {
		return "", fmt.Errorf("cannot convert IPAM result: %v", err)
	}

	log.Debugf("IPAM plugin %s ADD cniResult: %v", cfg.IPAM.Type, ipamResult)

	if len(ipamResult.IPs) > 0 {
		json, err := ipamResult.IPs[0].MarshalJSON()
		if err != nil {
			return "", fmt.Errorf("cannot marshall IPAM result: %v", err)
		}
		return string(json[:]), nil
	}
	return "", nil
}

func execIPAMDel(cfg *cniConfig, netconf []byte) error {
	log.Debugf("Calling external IPAM: %s", cfg.IPAM.Type)

	if cfg.IPAM.Type == hostLocalPluginName {
		// special case: need to convert usePodCidr to actual POD CIDR for this node
		netconf = replacePodCIDR(netconf, cfg.EtcdEndpoints)
	}

	err := ipam.ExecDel(cfg.IPAM.Type, netconf)
	if err != nil {
		return fmt.Errorf("IPAM plugin %s: DEL returned an error: %v", cfg.IPAM.Type, err)
	}

	log.Debugf("IPAM plugin %s DEL OK", cfg.IPAM.Type)
	return nil
}

func replacePodCIDR(netconf []byte, etcdEndpoints string) []byte {

	// unmarshall netconf data
	var cniConfig map[string]interface{}
	if err := json.Unmarshal(netconf, &cniConfig); err != nil {
		log.Errorf("Error by unmarshalling CNI config: %v", err)
		return netconf
	}

	ipamData, ok := cniConfig[cfgIpamKey].(map[string]interface{})
	if !ok {
		fmt.Printf("failed to parse host-local IPAM data; was expecting a dict, not: %v", cniConfig[cfgIpamKey])
	}

	// replace usePodCidr in subnet with an actual subnet
	subnet, _ := ipamData[cfgSubnetKey].(string)
	if strings.EqualFold(subnet, podCidrSubstKey) {
		ipamData[cfgSubnetKey] = getPodCIDR(etcdEndpoints)
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

func getPodCIDR(etcdEndpoints string) string {
	_, broker, err := createEtcdClient(etcdEndpoints)
	if err != nil {
		log.Errorf("Error by creating ETCD client: %v", err)
		return ""
	}

	hostName, err := os.Hostname()
	key := fmt.Sprintf("%s/%s", etcdNodePrefix, hostName)

	nodeInfo := &nodemodel.Node{}
	found, _, err := broker.GetValue(key, nodeInfo)
	if err != nil {
		log.Errorf("Error by getting ETCD value: %v", err)
		return ""
	}

	if !found {
		log.Errorf("ETCD key not found: %s", key)
		return ""
	}

	return nodeInfo.Pod_CIDR
}

func createEtcdClient(etcdEndpoints string) (*etcd.BytesConnectionEtcd, keyval.ProtoBroker, error) {

	if etcdEndpoints == "" {
		return nil, nil, errors.New("ETCD endpoints string is empty")
	}
	cfg := &etcd.Config{
		Endpoints:         strings.Split(etcdEndpoints, ","),
		InsecureTransport: true,
		DialTimeout:       10000000000,
	}

	etcdConfig, err := etcd.ConfigToClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	bDB, err := etcd.NewEtcdConnectionWithBytes(*etcdConfig, logging.DefaultLogger)
	if err != nil {
		return nil, nil, err
	}

	return bDB, kvproto.NewProtoWrapperWithSerializer(bDB, &keyval.SerializerJSON{}).NewBroker(etcdAgentPrefix), nil
}
