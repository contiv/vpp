package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/contiv/vpp/pkg/docker"
	"github.com/contiv/vpp/pkg/manager"
	"github.com/contiv/vpp/pkg/util/flags"
	"github.com/contiv/vpp/pkg/util/logs"
	"github.com/golang/glog"
	"github.com/spf13/pflag"
	"k8s.io/kubernetes/pkg/kubelet/server/streaming"
)

const (
	contivshimVersion = "0.0.1"
	// use port 24542 for dockershim streaming
	dockerStreamingServerPort = 25553
)

var (
	version = pflag.Bool("version", false, "Print version and exit")
	listen  = pflag.String("listen", "/var/run/contivshim.sock",
		"UNIX sockets to listen on, e.g. /var/run/contivshim.sock")
	etcdEndpoint = pflag.String("etcd-endpoint", "127.0.0.1:25552",
		"The endpoint for connecting to etcd data store grpc server, i.e. 127.0.0.1:25552")
	dockershimEndpoint = pflag.String("dockershim-endpoint", "/var/run/dockershim.sock",
		"The endpoint for connecting to dockershim grpc server, i.e. /var/run/dockershim.sock")
	dockerRuntimeEndpoint = pflag.String("docker-endpoint", "unix:///var/run/docker.sock",
		"Endpoint of Docker Runtime UNIX to communicate")
	streamingServerAddress = pflag.String("streaming-server-addr", "0.0.0.0",
		"IP address streaming server serves on, e.g. 0.0.0.0")
	cniNetDir = pflag.String("cni-net-dir", "/etc/cni/net.d",
		"Directory of CNI configuration file")
	cniPluginDir = pflag.String("cni-plugin-dir", "/opt/cni/bin",
		"Directory of CNI binary file")
	cgroupDriver = pflag.String("cgroup-driver", "cgroupfs", "Driver that the vppshim uses to manipulate cgroups on the host. *SHOULD BE SAME AS* kubelet cgroup driver configuration.  Possible values: 'cgroupfs', 'systemd'")
	rootDir      = pflag.String("root-directory", "/var/lib/contivshim", "Path to the contivshim root directory")
)

func main() {
	flags.InitFlags()
	logs.InitLogs()
	defer logs.FlushLogs()

	if *version {
		glog.Infof("Contivshim version: %s\n", contivshimVersion)
		os.Exit(0)
	}

	if *cgroupDriver != "cgroupfs" && *cgroupDriver != "systemd" {
		glog.Error("cgroup-driver flag should only be set as 'cgroupfs' or 'systemd'")
		os.Exit(1)
	}

	// 1. Initialize docker runtime and start its own streaming server
	dockershimRuntime, err := docker.NewDockerRuntime(
		*dockerRuntimeEndpoint,
		getDockerStreamingConfig(),
		*cniNetDir,
		*cniPluginDir,
		*cgroupDriver,
		filepath.Join(*rootDir, "docker"),
	)
	if err != nil {
		glog.Errorf("Initialize docker runtime failed: %v", err)
		os.Exit(1)
	}
	// 2. Create NewContivshimManager that manages passing the messages to Etcd and dockershim
	server, err := manager.NewContivshimManager(etcdEndpoint, dockershimRuntime, dockershimRuntime)
	if err != nil {
		glog.Errorf("Initialize contivshim server failed: %v", err)
		os.Exit(1)
	}
	// 3. Start Contivshim grpc server and register with kubelet
	glog.Infof("Starting contivshim grpc server...")
	fmt.Println(server.Serve(*listen))
}

// getDockerStreamingConfig creates the streaming configuration for docker streaming server using given port
func getDockerStreamingConfig() *streaming.Config {
	config := &streaming.Config{
		StreamIdleTimeout:               streaming.DefaultConfig.StreamIdleTimeout,
		StreamCreationTimeout:           streaming.DefaultConfig.StreamCreationTimeout,
		SupportedRemoteCommandProtocols: streaming.DefaultConfig.SupportedRemoteCommandProtocols,
		SupportedPortForwardProtocols:   streaming.DefaultConfig.SupportedPortForwardProtocols,
	}
	config.Addr = fmt.Sprintf("%s:%d", *streamingServerAddress, dockerStreamingServerPort)
	return config
}
