### Setting up a node with multiple NICs

* First, configure hardware interfaces in the VPP startup config, as
described [here](./VPP_CONFIG_CAVIUM.md#multi-nic-configuration).

* For each interface owned by Linux, you need to provide individual
  configuration for each interface used by VPP in the Node Configuration 
  for the node in the `contiv-vpp-arm64.yaml`. For example, if both `enP2p1s0f1` and
  `enP2p1s0f2` are known to Linux, you put the following stanza into the node's
  NodeConfig:
```
...
    NodeConfig:
    - NodeName: "ubuntu-1"
      StealInterface: "enP2p1s0f1"
      StealInterface: "enP2p1s0f2"
...
``` 
  If only `enP2p1s0f1` is known to Linux, you only put a line for `enP2p1s0f1` into the 
  above NodeConfig.

