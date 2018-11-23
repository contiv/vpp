# Configuration and Troubleshooting Tools

## contiv-netctl

`contiv-netctl` is a command line interface for querying the status
of Contiv-VPP vswitches in a K8s cluster that is using Contiv-VPP
CNI plugin. This overview covers contiv-netctl syntax, describes the
available commands, and provides common examples. `contiv-netctl` is
installed on the K8s-master host during the installation of the
Contiv-VPP CNI plugin.

### Syntax
Use the following syntax to run `contiv-netctl` commands from your
terminal window:

```
contiv-netctl [operation] [node] [parameters] [flags]
```

where operation, node, parameters, and flags are:

* `command`: specifies the query operation to be performed on one or
  more vswitches in the cluster
* `node`: optional, specifies the node where the query operation is
  to be executed. For some query operations, if node is not specified,
  the operation is performed on all nodes.
* `parameters`: optional, specifies parameters to the query operation
* `flags`: Specifies optional flags. Currently, only the -h flag is
  supported; when specified, help text for the specified operation(s) 
  is printed to stdout.

### Operations

The following table includes short descriptions and the general syntax
for `contiv-netctl` operations:

Operation | Syntax | Description
----------| -------|------------
`help` | `contiv-netctl help` | Prints out help about any command
`ipam` | `contiv-netctl ipam [NODE] [-h]` | Show ipam info for `[NODE]`, or for all nodes if `[NODE]` not specified
`nodes` | `contiv-netctl nodes [-h]` | Show vswitch summary status info
`pods` | `contiv-netctl pods [NODE] [-h]` | Show pods and their respective vpp-side interfaces for specified `[NODE]`, or for all nodes if `[NODE]` not specified
`vppcli` | `contiv-netctl vppcli NODE [vpp-dbg-cli-cmd] [-h]` | Execute the specified `[vpp-dbg-cli-cmd]` on the specified `NODE`
`vppdump` |`contiv-netctl vppdump NODE [vpp-agent-resource] [-h]` | Get the specified `[vpp-agent-resource]` from VPP Agent on the specified `NODE`

### Examples

```
// Print out help.
$ contiv-netctl

// Print out ipam information for all nodes.
$ contiv-netctl ipam

// Print out ipam information for node k8s-master.
$ contiv-netctl ipam k8s-master

// Print out node information for all nodes.
$ contiv-netctl nodes

// Print out pod information for all nodes.
$ contiv-netctl pods

// Print out ipam information for node k8s-mworker1.
$ contiv-netctl pods k8s-worker1

// Execute the VPP 'sh int addr' command on node k8s-mworker2.
$ contiv-netctl vppcli k8s-worker2 sh int addr

// Get the available REST resources from VPP Agent on node k8s-master.
$ contiv-netctl vppdump k8s-master

// Get the Bridge Domains resource from VPP Agent on node k8s-master.
$ contiv-netctl vppdump k8s-master bd
```

## Contiv -VPP Custom Resource Definitions (CRDs)

A resource is an endpoint in the [Kubernetes API][1] that stores a
collection of [API objects][2] of a certain kind. For example, the
built-in pods resource contains a collection of Pod objects. A [custom
resource][3] is an extension of the Kubernetes API that is not necessarily
available on every Kubernetes cluster. In other words, it represents a
customization of a particular Kubernetes installation.

Contiv-VPP defines the following custom resources:
* `nodeconfigs.nodeconfig.contiv.vpp`: used to configure Contiv-VPP
   vswitch parameters, such as the VPP GigE interface IP address or the
   vswitch Node ID.

   To configure a node using the configuration CRD, first create a
   manifest file, for example [here][4] or as shown below:
   ```
   # Configuration for node in the cluster
   apiVersion: nodeconfig.contiv.vpp/v1
   kind: NodeConfig
   metadata:
     name: k8s-master
   spec:
     mainVPPInterface:
       interfaceName: "GigabitEthernet0/8/0"
       ip: "192.168.16.1/24"
   ```
   and the use `kubectl` to apply the configuration:
   ```
   kubectl apply -f <configuration-file>
   ```
   You can also get the current cluster configration as follows:
   ```
   kubectl get nodeconfigs.nodeconfig.contiv.vpp -o json
   ```

* `telemetryreports.telemetry.contiv.vpp`: provides telemetry data from
  all Contiv-VPP vswitches in the cluster. The telemetry data is basically
  a dump of VPP state and a report on the health of the Contiv-VPP network
  provided by the network validator.

  To print the telemetry data to stdout, type:
  ```
  $ kubectl get telemetryreports.telemetry.contiv.vpp -o json
  ```
In order to use CRDs you need to:

* In the vagrant world edit the value of export
  CRD_DISABLED=${CRD_DISABLED:-true} to false found in this file:
  https://github.com/contiv/vpp/blob/master/vagrant/defaults

* In the manual setup use helm to generate the contiv-vpp.yaml with CRDs
  enabled:
  ```
  $ helm template --name foo --set contiv.crdNodeConfigurationDisabled=false --set contiv.ipamConfig.contivCIDR=10.128.0.0/14 $cvpp_dir/k8s/contiv-vpp > $cvpp_dir/k8s/contiv-vpp/foo.yaml
  ```

[1]: https://kubernetes.io/docs/reference/using-api/api-overview/
[2]: https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/
[3]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[4]: https://github.com/contiv/vpp/blob/master/k8s/node-config/config-example.yaml
