package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/nerdtakula/supervisor"
	"google.golang.org/grpc"
	yaml "gopkg.in/yaml.v2"

	"github.com/contiv/vpp/cmd/contiv-stn/model/stn"
	"github.com/contiv/vpp/plugins/contiv"
)

const (
	defaultConfigFile     = "/etc/agent/contiv.yaml"
	defaultSupervisorPort = 9001
	defaultStnServerPort  = 50051
)

var (
	configFile     = flag.String("config", defaultConfigFile, "location of the contiv-agent config file")
	supervisorPort = flag.Int("supervisor", defaultSupervisorPort, "management port of the supervisor process")
	stnServerPort  = flag.Int("stn-server", defaultStnServerPort, "port where STN GRPC server listens for connections")
)

// stealNIC requests stealing the specified NIC from the STN GRPC server.
func stealNIC(nicName string) error {
	log.Printf("Stealing the NIC: %s", nicName)

	// connect to STN GRPC server
	conn, err := grpc.Dial(fmt.Sprintf(":%d", *stnServerPort), grpc.WithInsecure())
	if err != nil {
		log.Printf("Unable to connect to STN GRPC: %v", err)
		return err
	}
	defer conn.Close()
	c := stn.NewSTNClient(conn)

	// request stealing the interface
	reply, err := c.StealInterface(context.Background(), &stn.STNRequest{
		InterfaceName: nicName,
	})
	if err != nil {
		log.Printf("Error by executing STN GRPC: %v", err)
		return err
	}

	// TODO: return the reply
	log.Println(reply)
	return nil
}

// parseSTNConfig parses the config file and looks up for STN configuration.
// In case that STN was requested for this node, returns the interface to be stealed.
func parseSTNConfig() (string, error) {
	var config contiv.Config

	// read config YAML
	yamlFile, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Printf("Error by reading config file %s: %v", *configFile, err)
		return "", err
	}

	// unmarshall the YAML
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Printf("Error by unmarshaling YAML: %v", err)
		return "", err
	}

	// try to find node config and return STN interface name if found
	nodeName := os.Getenv("MICROSERVICE_LABEL")
	for _, nc := range config.NodeConfig {
		if nc.NodeName == nodeName {
			log.Printf("Found interface to be stealed: %s", nc.StealInterface)
			return nc.StealInterface, nil
		}
	}

	return "", nil
}

func main() {
	flag.Parse()

	// check whether STN is required and get NIC name
	nicToSteal, err := parseSTNConfig()
	if err != nil {
		log.Fatalf("Error by parsing STN config: %v", err)
	}

	if nicToSteal != "" {
		// steal the NIC
		err := stealNIC(nicToSteal)
		if err != nil {
			log.Fatalf("Error by steling the NIC %s: %v", nicToSteal, err)
		}
	}

	// connect to supervisor API
	client := supervisor.New("localhost", *supervisorPort, "", "")

	// start VPP
	_, err = client.StartProcess("vpp", false)
	if err != nil {
		log.Fatalf("Error by starting VPP process: %v", err)
	}

	if nicToSteal != "" {
		// TODO: configure connectivity on VPP

		// TODO: configure connectivity on host

		// TODO: persist VPP config in ETCD
	}

	// start contiv-agent
	_, err = client.StartProcess("contiv-agent", false)
	if err != nil {
		log.Fatalf("Error by starting contiv-agent process: %v", err)
	}
}
