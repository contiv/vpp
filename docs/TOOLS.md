# Configuration and Troubleshooting Tools

## contiv-netctl

`contiv-netctl` is a is a command line interface for querying the status
of Contiv-VPP vswitches in aK8s cluster that usea the using Contiv-VPP
CNI plugin. This overview covers contv-netctl syntax, describes the
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
* `node`: optional, specifies the node on which the query operation is
  to be performed. For some query operations, if node is not specified,
  the operation is performed on all nodes.
* `parameters`: optional, specifies parameters to the query operation
* `flags`: Specifies optional flags. Currently, only the -h flag is
  supported - when specified, help test for the operation(s) is printed
  to stdout.

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

