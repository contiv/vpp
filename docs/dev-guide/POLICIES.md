# Kubernetes network policies in Contiv/VPP

## Overview

Kubernetes network policies allow to specify how groups of pods are allowed
to communicate with each other and other network endpoints. Each policy is represented
as an instance of the K8s resource `NetworkPolicy`. Using labels a grouping of pods
is selected for which a list of rules specifies what traffic is allowed to and from
the pods. Contiv/VPP implements Kubernetes Network API, including the latest
features, such as egress policies and CIDRs.

For VPP as a packet-processing stack this is an overly abstract definition
for access control between endpoints. K8s Policies with their rules need to be
mapped to a semantically equivalent set of basic **6-tuple rules**:
```
(source IP, source port, destination IP, destination port, protocol, action)
```
where `protocol` is one of the `TCP`, `UDP`, `ANY` and `action` is either `Deny`
or `Permit`. Using [ligato/vpp-agent][ligato-vpp-agent], these rules are then
installed into VPP as ACLs from the [VPP/ACL plugin][acl-plugin], applied
for the standard path of packet-processing in VPP consisting of graph nodes,
but also as L4 session rules for the [VPPTCP network stack][vpptcp]
(integration of Contiv/VPP with Envoy via VPPTCP is planned for the future).

## Policy plugin

The mapping of Kubernetes network policies to ACLs and VPPTCP session rules
is implemented by the [policy plugin][policy-plugin] using a **data-flow** based approach.
The plugin is split into multiple components stacked on top of each other,
with data moving in the direction from the up to the bottom. Each layer obtains
policy-related data from the layer above and performs transformation that yields
a less abstract representation for the layer below. This way the abstraction level
decreases with each layer until it reaches the format of policy rules used by the target
network stack. On the top there are K8s state data as reflected into ETCD by KSR.
On the very bottom there is a network stack into which the policies are rendered
(extensible beyond VPP, see [Renderers](#renderers)).
Layers in-between perform policy processing with the assistance of in-memory caches.

![Policy plugin layers][layers-diagram]

Every layer is described here in detail with an extra focus on data transformations,
starting from the top and including references to the actual source code.

### Policy Plugin skeleton

The [skeleton of the policy plugin][policy-plugin] implements the [Plugin interface][plugin-intf]
which makes it pluggable with the CN-Infra framework.

The Resync procedure of the policy plugin waits until the resync of the Contiv
plugin has finalized. This ensures that connectivity between pods and VPP is established
before any rules are installed.

Inside the `Init` method all the layers are initializes and dependency injection
is performed - every layer needs to have injected at least the layer below, so that
it can output transformed data further.

Policy plugin subscribes to ETCD in `subscribeWatcher()` to watch for changes
related to [network policies][policy-model], [pods][pod-model] and [namespaces][ns-model]
as reflected into the data store by KSR using K8s API. Apart from policies,
state data of pods and namespaces must also be watched to learn their current attachment
of labels, which are then referenced by policies.
The plugin propagates these datasync events without any processing into the Policy Cache.

### Cache

Unpacks datasync [update][cache-data-change] and [resync][cache-data-resync]
events and stores the current full snapshot of policy-related K8s state data
in-memory using [idxmap][idxmap]-s from the CN-infra framework. The cache provides
[API][cache-api] to get notified whenever policy, pod or namespace state data changes.
The notifications are propagated via callbacks, one for a resource instance at a time.
A watcher must implement the `PolicyCacheWatcher` interface with methods such
as `AddPolicy()`, `UpdatePolicy()`, etc. This interface is implemented by the Policy
Processor - the first layer in the data-flow stack that performs actual data
transformations. Additionally, the cache exposes various lookup methods
(e.g. get pods by label selector), which are used by all the layers (but mostly
by the processor).

### Processor

Policy processor gets notified by the Cache whenever a change related to policy
configuration occurs. Additionally, it receives a full snapshot from the cache
during the Resync event.

For each change, the processor decides if the re-configuration needs to be postponed
until more data are available. Typically, policies cannot be installed for a pod
until it has been assigned an IP address.

If a change carries enough information, processor determines the list of pods
with a **possibly outdated** policy configuration (all for RESYNC):
 * For a changed policy this includes all the pods that the policy had assigned
   before and after the change.
 * For a changed pod (labels, IP address), this results in re-configuration
   of all pods with a policy referencing the changed pod before or after the change.
 * For a changed namespace, all pods with a policy referencing the changed namespace
   before or after the change need to be re-configured.

_Note_: re-configuration triggered by the processor for a given pod does not
        necessarily causes the rules to be re-written in the network stacks.
        The layers below, most notably the [renderers](#renderers),
        ensure that only the minimal set of changes - if any - are applied to get
        the configuration in-sync with the K8s state.

For each pod with possibly outdated policy configuration, the Processor calculates
the set of policies currently assigned to it. The policies are then converted
to a less-abstract `ContivPolicy` type from [Configurator API][configurator-api].
`ContivPolicy` is simpler in that it has:
 * evaluated Label Selectors into the matching list of pods
 * translated port names into numbers
 * namespaces expanded into the list of pods that they contain
Pod data with the assigned set of Contiv policies are then passed further into
to the Configurator for re-configuration.

### Configurator

Main task of the Configurator is to translate ContivPolicy into semantically
equivalent set of basic 6-tuple rules, split into ingress and egress side
from the **vswitch point of view**. 6-tuple is defined as type ContivRule
in the [Renderer API][renderer-api].
The rules are then installed by the layer below - Renderer(s). To support multiple
underlying network stacks, the configurator allows to register multiple renderers,
each receiving the same data with the responsibility for the management of the access
control in its own network stack.

The procedure of translating a set of Contiv policies into ingress/egress rules
can be described by the following pseudo-code:
```
GenerateRules
    input: direction (ingress or egress - pod point of view), set of ContivPolicies
    output: list of ContivRules - opposite direction, but from the vswitch point of view

    for every policy:
        if the policy doesn't apply to this direction:
            skip

        for every match: // match = all endpoints OR set of pods + set of IPBlocks referenced by the policy

            // Cache is used to get IP address of the pod.
            get IP address for every matched pod

            // Since 6-tuples do not define port ranges, we cannot efficiently
            // implement IPBlocks with excluded sub-ranges by overlapping PERMIT+DENY
            // rules. Instead we perform subtraction over IP subnets
            // (function subtractSubnet() from configurator_impl.go) which results
            // in multiple PERMIT-only rules (with one deny-the-rest at the end).
            subtract excluded subnets from the CIDR of every matched IPBlock

            // Generate 6-tuples (src-IP, src-port, dst-IP, dst-port, protocol, action)
            if match is all endpoints:
                if match includes all ports:
                    add rule (ANY, ANY, ANY, ANY, ANY, PERMIT)
                else:
                    for every matched port, protocol:
                        add rule (ANY, ANY, ANY, port, protocol, PERMIT)
            else:
                for every matched pod's IP address:
                    if match includes all ports:
                        if direction is ingress:
                            add rule (pod-IP, ANY, ANY, ANY, ANY, PERMIT)
                        else:
                            add rule (ANY, ANY, port-IP, ANY, ANY, PERMIT)
                    else:
                        for every matched port, protocol:
                            if direction is ingress:
                                add rule (pod-IP, ANY, ANY, port, protocol, PERMIT)
                            else:
                                add rule (ANY, ANY, port-IP, port, protocol, PERMIT)

                for every matched IPBlock (after subtraction of excluded sub-ranges):
                    if match includes all ports:
                        if direction is ingress:
                            add rule (IPBlock, ANY, ANY, ANY, ANY, PERMIT)
                        else:
                            add rule (ANY, ANY, IPBlock, ANY, ANY, PERMIT)
                    else:
                        for every matched port, protocol:
                            if direction is ingress:
                                add rule (IPBlock, ANY, ANY, port, protocol, PERMIT)
                            else:
                                add rule (ANY, ANY, IPBlock, port, protocol, PERMIT)

    // Deny the rest of the traffic.
    if not all was PERMITed:
        add rule (ANY, ANY, ANY, ANY, ANY, DENY)

```

`GenerateRules` is implemented by `PolicyConfiguratorTxn.generateRules()`
and it is executed for both directions to obtain separate lists of ingress and egress
Contiv rules.

#### ContivRule semantics

Since the pod for which the rules are generated is given, the ingress rules have
the source IP unset, i.e. 0.0.0.0/ (match all). Conversely, egress rules have
their destination IP unset. The ingress rules are supposed to be applied for all
the traffic entering VPP from the given pod, whereas egress rules should be confronted
with all the traffic leaving VPP towards the pod.

The order at which the rules are applied for a given pod is important as well.
The renderer which applies the rules for the destination network stack has 3 valid
options of ordering:
 1. Apply the rules in the exact same order as passed by the Configurator
 2. Apply PERMIT rules before DENY rules: this is possible because there is
    always only one DENY rule that blocks traffic not matched by any PERMIT rule.
 3. Apply more-specific rule, i.e covering less traffic, before less-specific ones.
    ContivRule-s have a total order defined on them using the method `ContivRule.Compare(other)`.
    It holds that if `cr1` matches subset of the traffic matched by `cr2`, then `cr1<cr2`.
    This ordering may be helpful if the destination network stack uses
    **longest prefix match** algorithm for logarithmic rule lookup, as opposed
    to list-based linear lookup.

Not every network stack supports access-control for both directions, however.
Additionally, [services][services-dev-guide] allow to reference a group of pods
by VIP but rules only consider real pod IP addresses. This means that translation
and load-balancing have to happen before the ingress rules are applied, which
is not possible in VPP. The renderers therefore have to further transform and combine
ingress and egress rules into a single direction, see [rule transformations][rule-transformations].

### Renderers

Policy Renderer implements rendering (= installation) of Contiv rules for a specific network
stack. What the rules get mapped into and how the rendering operates may be different
for each network stack. The renderer only has to implement the [PolicyRendererAPI interface][renderer-api]
and then it can be registered with the Configurator. Another requirement, which
obviously cannot be enforced by the interface, is that the rendered access control
configuration in the underlying stack semantically reflects the last received
ingress & egress rules for every pod. The semantics of rules is described
in [Renderer API][renderer-api] and also in this document, see section
[ContivRule semantics](#contivrule-semantics).

The 6-tuple ContivRule has been designed to be as simple as possible while still
being expressible enough to describe Kubernetes network policies.
This should allow to write renderers for even the most basic access control implementations.
Still not every network stack provides AC separately for ingress and egress directions.
Furthermore, the rules should apply to traffic after service VIPs were translated
to pods selected by load-balancer. As is the case with VPP/ACL plugin, this is often
not possible to ensure with ingress rules.
Another potential limitations may be that the target AC does not operate per-interface,
but instead applies rules installed inside a single global table of rules.
Further transformation of rules may be therefore necessary even at the level of
renderers. We provide [Renderer Cache][renderer-cache], used by both ACL and VPPTCP
renderers, which not only maintains a snapshot of currently rendered rules,
but also allows to work around the aforementioned limitations by combining
ingress with egress as described in the next section.

#### Rule transformations

Both VPP/ACL and VPPTCP have their limitations that prevent from installing
ingress and egress rules received from the configurator without any changes.

For VPP/ACL the **ingress ACLs** cannot be used with the interfaces connecting pods.
The reason is that traffic flows through these ACLs before it reaches nat44* graph
nodes, meaning that the translation of service VIPs executes later.
However, K8s network policies run below services in the sense that they are meant
to be applied against the real pod IP address and not the virtual ones.

VPPTCP, on the other hand, does not even provide per-interface egress AC.
Every namespace (connection with a pod) provides its own local table of session rules,
which is only applied against traffic entering VPP from the namespace but
not confronted with the connections initiated in the egress direction.
Egress side is matched by a single per-node global table. This table is bypassed,
however, if communicating pods are deployed on the same node (`fall-through` optimization).

The rules for ingress and egress direction are therefore combined into a single
selected direction - **egress for ACL** and **ingress for VPPTCP**.
For simplicity, we will now describe the algorithm specifically for the egress
side used by ACLs. The same algorithm is used by VPPTCP renderer (implementation
is parametrized), only source and destination IPs are swapped and the resulting
direction is ingress.

To calculate pod's egress rules that include restrictions imposed by ingress
rules of other pods, the following algorithm expressed in pseudo-code is used:
```
CombineRules
    input: target pod - denoted as pod1, pod1's egress rules, every other *known* pod's ingress rules
    output: pod1's egress rules intersected with ingress rules of other pods

    for every other known pod - denoted as pod2:
        get a set of TCP, UDP ports that pod2 can access on pod1 by pod2's ingress rules
            - denote ingressTCP & ingressUDP

        get a set of TCP, UDP ports that pod1 has opened for pod1 by pod1's egress rules
            - denote egressTCP & egressUDP

        if egressTCP is not subset of ingressTCP
            OR
           egressUDP is not subset of ingressUDP:

            from pod1's egress table remove all rules with source IP == pod2-IP

            interset ingressTCP with egressTCP - denote allowedTCP

            interset ingressUDP with egressUDP - denote allowedUDP

            // Generate 6-tuples (src-IP, src-port, dst-IP, dst-port, protocol, action):
            for every port from allowedTCP:
                insert into pod1's egress table rule (pod2-IP, ANY, ANY, port, TCP, PERMIT)

            for every port from allowedUDP:
                insert into pod1's egress table rule (pod2-IP, ANY, ANY, port, UDP, PERMIT)

            // deny the rest of the traffic from pod2 to pod1:
            insert into pod1's egress table rule (pod2-IP, ANY, ANY, ANY, ANY, DENY)
```

Notice that pod's egress rules are combined with only other **known** pods.
The renderer is not supplied with policy configuration for pods without any policy assigned
or deployed on other nodes. Pod without any policy is open to any traffic therefore
there are no ingress rules to combine with. Pods deployed on other nodes, however,
may have restrictions imposed on the ingress side. Therefore `CombineRules` is not
sufficient on its own to ensure that ingress rules are reflected into egress ACLs.
It is thus necessary to filter traffic leaving the node based on ingress rules
of all pods deployed on it. Ingress rules of all local pods are unified
into a single global table assigned to the egress side of the interfaces connecting
the node with the rest of the cluster.

Global table is build using the following algorithm:
```
BuildGlobalTable:
    input: ingress rules of locally deployed pods
    output: single egress "global" table applying all ingress rules for traffic leaving the node

    create empty global table

    for every locally deployed pod:

        for every pod's ingress rule:

            change rule's source IP from ANY to pod's IP address

            add rule into the global table

    // add rule to allow the rest of the traffic
    add into global table rule  (ANY, ANY, ANY, ANY, ANY, PERMIT)
```

Again, the actual implementation is parametrized allowing to choose the direction
for which the global table should be build for:
 1. ingress rules of locally deployed pods -> single egress global table: used by ACL
 2. egress rules of locally deployed pods -> single ingress global table: used by VPPTCP

With these transformations, the order at which the rules can be applied is more strict than
when they originally arrived from the configurator - the order between PERMIT and DENY rules
now matters.
The renderer which applies the rules for the destination network stack has now only two
valid options of ordering:
 1. Apply the rules in the exact same order as returned by the Cache for each table.
    Used by the ACL Renderer.
 2. Apply more-specific rule before less-specific ones, i.e. the **longest prefix match**
    algorithm.
    Used by the VPPTCP Renderer.

#### Renderer cache

Both VPPTCP and ACL renderer create their own instance of the same [Renderer Cache][cache-api].
The cache maintains a snapshot of all rules currently rendered and allows to easily
calculate the minimal set of changes that need to be applied in a given transaction.
The rules are inserted into the cache as received from the configurator - unprocessed
and split into ingress and egress sides. Internally the cache performs the transformations
described [in the section above](#rule-transformations). Algorithm `CombineRules`
is implemented by `RendererCacheTxn.buildLocalTable()`. The implementation is parametrized,
destination to which the rules should be combined is selected during the cache initialization
(egress for ACL, ingress for VPPTCP).

The rules are grouped into tables represented by the type `ContivRuleTable` from the
Cache [API][cache-api] and the full configuration is represented as a list of local tables,
applied on the ingress or the egress side of pods, and a single global table - generated
using the `BuildGlobalTable` algorithm implemented by `RendererCacheTxn.rebuildGlobalTable()`,
applied onto the interfaces connecting the node with the rest of the cluster.

The list of local tables is minimalistic in the sense that pods with the same
set of rules will share the same local table. Whether shared tables are installed
in one instance or as separate copies for each associated pod is up to the renderer.
Usually this is determined by the capabilities of the destination network stack,
e.g. VPP/ACL plugin allows to assign single ACL to multiple interfaces, but VPPTCP
requires to build session rule table individually for each namespace.

#### ACL Renderer

[ACL Renderer][acl-renderer] installs ContivRule-s into VPP as ACLs from
[VPP/ACP plugin][acl-plugin]. The renderer uses [cache](#renderer-cache) to convert
ingress and egress rules into per-pod egress ACLs (local tables), each assigned
to TAP connecting VPP with the corresponding pod, and a single egress ACL (global table)
assigned to interfaces connecting node with the rest of the cluster: Gbe interfaces,
loop in the BD with VXLANs and TAP connecting VPP with the host. Pods with the same
policy configuration share the same ACL.

Key method is `RendererTxn.renderACL()` implementing conversion between an instance
of `ContivRuleTable` into the [protobuf-based representation of ACL][acl-model] used
in the northbound API of [ligato/vpp-agent][ligato-vpp-agent]. Every ContivRule
is mapped into a single `Acl.Rule`. `Match.IpRule` is filled with values from
the 6-tuple - port ranges always include either all ports or a single one (the rules
are not compacted together). Generated ACL are sent to [ligato/vpp-agent][ligato-vpp-agent]
via [local client][local-client], which installs them into VPP through binary APIs.
For each transaction, the cache is used to determine the minimal set of ACLs that
need to be sent to vpp-agent to be added/updated or deleted.

By splitting rules into ingress and egress, K8s network policies allow to block
connection of certain parameters in one direction, while the same connection
can be allowed if is is initiated in the opposite direction. For ACLs it means
that if the egress ACL of the destination pod allows connection-initiating SYN packet,
the egress ACL of the source pod should not block the replied SYN-ACK or any other
packet of that connection. This behaviour is achieved by attaching a so called
`Reflective ACL` - allowing + **reflecting** all the traffic - onto to ingress side
of every pod with non-empty egress ACL. The effect is that SYN packet coming to VPP
from a pod automatically creates a free pass for replies returning to the pod.
The restrictions imposed by policies are therefore always applied only by the destination
pod's egress ACL or by the global (egress) ACL, not by the source pod's egress ACL.
It is important to note that connection is marked for reflection before it goes
through the NAT, i.e. with possibly VIP as the destination. This is OK because
the replies have their source already SNAT-ed back to VIP before the packet
travels through egress ACL of the source pod, matching the entry for reflection.

![ACL rendering][acl-rendering-diagram]

#### VPPTCP Renderer

[VPPTCP Renderer][vpptcp-renderer] installs ContivRule-s into VPP as session rules
for the VPPTCP network stack. The renderer uses [cache](#renderer-cache) to convert
ingress and egress rules into per-namespace (= pod) ingress local tables
and a single ingress global table.

VPPTCP uses a slightly different representation of the policy rule denoted `SessionRule`
(tuple with more entries). When put into the context of the target table, ContivRule
can be easily mapped to SessionRule(s) - this is implemented by `convertContivRule()`
from [session_rule.go][session-rule].

Session rules are installed into VPP **directly through GoVPP** (i.e. not using ligato/vpp-agent).
The cache is used to calculate the minimal number of changes needed to apply
to get the session rules in-sync with the configuration of K8s policies.

![Rendering of VPPTCP session rules][session-rules-rendering-diagram]


[layers-diagram]: policy-plugin-layers.png "Layering of the Policy plugin"
[acl-rendering-diagram]: acl-rendering.png "ACL rendering"
[session-rules-rendering-diagram]: session-rules-rendering.png "Rendering of VPPTCP session rules"
[services-dev-guide]: SERVICES.md
[ligato-vpp-agent]: http://github.com/ligato/vpp-agent
[local-client]: http://github.com/ligato/vpp-agent/tree/pantheon-dev/clientv1
[acl-plugin]: http://github.com/vpp-dev/vpp/tree/stable-1801-contiv/src/plugins/acl
[vpptcp]: http://github.com/vpp-dev/vpp/tree/stable-1801-contiv/src/vnet/session
[policy-plugin]: http://github.com/contiv/vpp/tree/master/plugins/policy/plugin_impl_policy.go
[plugin-intf]: http://github.com/ligato/cn-infra/tree/master/core/plugin_spi.go
[policy-model]: http://github.com/contiv/vpp/blob/master/plugins/ksr/model/policy/policy.proto
[pod-model]: http://github.com/contiv/vpp/blob/master/plugins/ksr/model/pod/pod.proto
[ns-model]: http://github.com/contiv/vpp/blob/master/plugins/ksr/model/namespace/namespace.proto
[idxmap]: http://github.com/ligato/cn-infra/tree/master/idxmap
[cache-api]: http://github.com/contiv/vpp/tree/master/plugins/policy/cache/cache_api.go
[cache-data-change]: http://github.com/contiv/vpp/tree/master/plugins/policy/cache/data_change.go
[cache-data-resync]: http://github.com/contiv/vpp/tree/master/plugins/policy/cache/data_resync.go
[configurator-api]: http://github.com/contiv/vpp/tree/master/plugins/policy/configurator/configurator_api.go
[renderer-api]: http://github.com/contiv/vpp/blob/master/plugins/policy/renderer/api.go
[renderer-cache]: http://github.com/contiv/vpp/blob/master/plugins/policy/renderer/cache/cache_api.go
[acl-renderer]: http://github.com/contiv/vpp/blob/master/plugins/policy/renderer/acl/acl_renderer.go
[acl-model]: http://github.com/ligato/vpp-agent/blob/pantheon-dev/plugins/defaultplugins/common/model/acl/acl.proto
[vpptcp-renderer]: http://github.com/contiv/vpp/tree/master/plugins/policy/renderer/vpptcp
[session-rule]: http://github.com/contiv/vpp/blob/master/plugins/policy/renderer/vpptcp/rule/session_rule.go