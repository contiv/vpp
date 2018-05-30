# Packet flow in Contiv/VPP

This guide provides a detailed description of paths traversed by request and response
packets inside Contiv/VPP Kubernetes cluster under different situations.

## Index

1. [Pod to Pod on the same node](#pod-to-pod-on-the-same-node)
2. [Pod to Pod on another node](#pod-to-pod-on-another-node)
3. [Pod to Pod in the host network stack](#pod-to-pod-in-the-host-network-stack)
4. [Host to Pod](#host-to-pod)
5. [Pod To Internet](#pod-to-internet)
6. [Pod to Service with chosen backend on the same node](#pod-to-service-with-chosen-backend-on-the-same-node)
7. [Pod to Service with chosen backend on another node](#pod-to-service-with-chosen-backend-on-another-node)
8. [Pod to Service with chosen backend in the host network stack](#pod-to-service-with-chosen-backend-in-the-host-network-stack)
9. [Host to Service](#host-to-service)

## Pod to Pod on the same node

### Request

Request sent from a "client" pod with the source address `clientIP:clientPort` destined
to `serverIP:serverPort` of another "server" pod on the same node:

1. Inside the client pod, destination `serverIP` matches the default route configured
   for the pod by `remoteCNIserver.podDefaultRouteFromRequest()`.
    * default gateway IP address is the same for all pods on the same node - returned
      by `IPAM.PodGatewayIP()` as the first unicast IP address from the subset of `PodSubnetCIDR`
      allocated for the node. **Pod default GW IP is kept virtual** and never assigned
      to any pod or interface inside VPP. Do not confuse pod's TAP interface IP
      address on the VPP side with the default gateway. The IP address assigned
      on the VPP-side of the pod-VPP interconnection actually plays no role in the
      packet traversal, it serves merely as a marker for VPP to put the TAP
      interface into the L3 mode.
2. Link-local route installed by `remoteCNIserver.podLinkRouteFromRequest()` informs
   the host stack that `PodGatewayIP` is on the same L2 network as the pod's `eth0`
   interface, even though the pod IP address is prefixed with `/32`.
3. Static ARP entry configured by `remoteCNIserver.podArpEntry()` maps `PodGatewayIP`
   to the MAC address of the VPP side of the pod's TAP interface, i.e. every pod
   translates `PodGatewayIP` to a different hardware address.
4. Packet arrives to VPP either through the `virtio-input` if TAP version 2 is used,
   or through `tapcli-rx` for TAPv1.
5. If the client pod is referenced by ingress or egress policies, the (ingress)
   `Reflective ACL` will be traversed (node `acl-plugin-in-ip4-fa`), **allowing
   and reflecting the connection** (study [Policy dev guide][policy-dev-guid] to learn why).
6. `nat44-out2in` node checks if the destination address should be translated
   as external IP into a local IP using any of the static mappings installed
   by the [service plugin][services-dev-guid] - in this case the destination
   is a real pod IP address, thus **no translation occurs** (`session index -1`
   in the packet trace).
7. Destination IP address matches static route installed for the server pod
   by `remoteCNIserver.vppRouteFromRequest()`. The server pod's TAP interface
   is selected for the output.
8. If the server pod is referenced by ingress or egress policies, the **combined
   ingress & egress policy rules installed as a single egress ACL** will be checked
   by the node `acl-plugin-out-ip4-fa`.
   The following two conditions must be true for the connection to be allowed:
   * the client pod allows connections destined to `serverIP:serverPort`
   * the server pod allows connections from `clientIP` to port `serverPort`
9. Static ARP entry configured by `remoteCNIserver.vppArpEntry()` maps `serverIP`
   to the hardware address of the server pod's `eth0` interface. It is required
   by the STN plugin that all pods use the same MAC address `00:00:00:00:00:02`.
10. Request arrives to the server pod's host stack.    

Example SYN packet sent from client `10.1.1.12:39820` to server `10.1.1.9:8080`:
```
SYN:
----
01:48:51:256986: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:48:51:256990: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:69:99:eb:9d
01:48:51:256993: ip4-input
  TCP: 10.1.1.12 -> 10.1.1.9
    tos 0x00, ttl 64, length 60, checksum 0xf087
    fragment id 0x341e, flags DONT_FRAGMENT
  TCP: 39820 -> 8080
    seq. 0x8c66e434 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xc3de
01:48:51:256995: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 7, next index 1, action: 2, match: acl 1 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0c01010a00000000 0000000000000000 0901010a00000000 000700061f909b8c 0702ffff00000007
   input sw_if_index 7 (lsb16 7) l3 ip4 10.1.1.12 -> 10.1.1.9 l4 proto 6 l4_valid 1 port 39820 -> 8080 tcp flags (valid) 02 rsvd 0
01:48:51:257002: nat44-out2in
  NAT44_OUT2IN: sw_if_index 7, next index 1, session index -1
01:48:51:257008: ip4-lookup
  fib 0 dpo-idx 12 flow hash: 0x00000000
  TCP: 10.1.1.12 -> 10.1.1.9
    tos 0x00, ttl 64, length 60, checksum 0xf087
    fragment id 0x341e, flags DONT_FRAGMENT
  TCP: 39820 -> 8080
    seq. 0x8c66e434 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xc3de
01:48:51:257011: ip4-rewrite
  tx_sw_if_index 11 dpo-idx 12 : ipv4 via 10.1.1.9 tap8: 00000000000202fe167939cb0800 flow hash: 0x00000000
  00000000: 00000000000202fe167939cb08004500003c341e40003f06f1870a01010c0a01
  00000020: 01099b8c1f908c66e43400000000a0027210c3de0000020405b40402
01:48:51:257013: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 11, next index 1, action: 1, match: acl 0 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0c01010a00000000 0000000000000000 0901010a00000000 000b00061f909b8c 0502ffff0000000b
   output sw_if_index 11 (lsb16 11) l3 ip4 10.1.1.12 -> 10.1.1.9 l4 proto 6 l4_valid 1 port 39820 -> 8080 tcp flags (valid) 02 rsvd 0
01:48:51:257016: tap8-output
  tap8
  IP4: 02:fe:16:79:39:cb -> 00:00:00:00:00:02
  TCP: 10.1.1.12 -> 10.1.1.9
    tos 0x00, ttl 63, length 60, checksum 0xf187
    fragment id 0x341e, flags DONT_FRAGMENT
  TCP: 39820 -> 8080
    seq. 0x8c66e434 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xc3de
```

### Response

Response sent from the pod with the server application `serverIP:serverPort` back
to the client `clientIP:clientPort` on the same node:

1. Default route + Link-local route + static ARP entry are used to sent
   the response to VPP via pod's `eth0` TAP interface (see the request flow,
   steps 1.-4., to learn the details)  
2. If the server pod is referenced by ingress or egress policies, the (ingress)
   `Reflective ACL` will be traversed (node `acl-plugin-in-ip4-fa`), **allowing
   and reflecting the connection**. The reflection has no effect in this case,
   since the connection was already allowed in the direction of the request.
3. `nat44-in2out` node checks if the source address should be translated as local IP
   into an external IP using any of the static mappings installed
   by the [service plugin][services-dev-guid] - in this case the server was accessed
   directly, not via service VIP, thus **no translation occurs**
   (`session -1` in the packet trace).
4. Destination IP address matches static route installed for the client pod
   by `remoteCNIserver.vppRouteFromRequest()`. The client pod's TAP interface
   is selected for the output.
5. If the client pod is referenced by ingress or egress policies, the combined
   ingress & egress policy rules installed as a single egress ACL will be checked
   by the node `acl-plugin-out-ip4-fa`.
   The desired behaviour is, however, to always allow connection if it has got
   this far - the **policies should be only checked in the direction of the request**.
   The `Reflective ACL` has already created a free pass for all responses in the
   connection, thus the client's egress ACL is ignored.
6. Static ARP entry configured by `remoteCNIserver.vppArpEntry()` maps `clientIP`
   to hardware address of the client pod's `eth0` interface. It is required
   by the STN plugin that all pods use the same MAC address `00:00:00:00:00:02`.
7. Request arrives to the client pod's host stack.

Example SYN-ACK packet sent from server `10.1.1.9:8080` back to client `10.1.1.12:39820`:
```
SYN-ACK:
--------
01:48:51:257049: virtio-input
  virtio: hw_if_index 11 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:48:51:257049: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:16:79:39:cb
01:48:51:257051: ip4-input
  TCP: 10.1.1.9 -> 10.1.1.12
    tos 0x00, ttl 64, length 60, checksum 0x24a6
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 39820
    seq. 0x0db7e410 ack 0x8c66e435
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x02b3
01:48:51:257051: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 11, next index 2, action: 2, match: acl 1 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0901010a00000000 0000000000000000 0c01010a00000000 000b00069b8c1f90 0712ffff0000000b
   input sw_if_index 11 (lsb16 11) l3 ip4 10.1.1.9 -> 10.1.1.12 l4 proto 6 l4_valid 1 port 8080 -> 39820 tcp flags (valid) 12 rsvd 0
01:48:51:257056: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 11, next index 3, session -1
01:48:51:257057: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 11, next index 0, session -1
01:48:51:257059: ip4-lookup
  fib 0 dpo-idx 9 flow hash: 0x00000000
  TCP: 10.1.1.9 -> 10.1.1.12
    tos 0x00, ttl 64, length 60, checksum 0x24a6
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 39820
    seq. 0x0db7e410 ack 0x8c66e435
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x02b3
01:48:51:257060: ip4-rewrite
  tx_sw_if_index 7 dpo-idx 9 : ipv4 via 10.1.1.12 tap11: 00000000000202fe6999eb9d0800 flow hash: 0x00000000
  00000000: 00000000000202fe6999eb9d08004500003c000040003f0625a60a0101090a01
  00000020: 010c1f909b8c0db7e4108c66e435a012712002b30000020405b40402
01:48:51:257060: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 7, next index 1, action: 3, match: acl -1 rule 170 trace_bits 80000000
  pkt info 0000000000000000 0901010a00000000 0000000000000000 0c01010a00000000 000700069b8c1f90 0512ffff00000007
   output sw_if_index 7 (lsb16 7) l3 ip4 10.1.1.9 -> 10.1.1.12 l4 proto 6 l4_valid 1 port 8080 -> 39820 tcp flags (valid) 12 rsvd 0
01:48:51:257061: tap11-output
  tap11
  IP4: 02:fe:69:99:eb:9d -> 00:00:00:00:00:02
  TCP: 10.1.1.9 -> 10.1.1.12
    tos 0x00, ttl 63, length 60, checksum 0x25a6
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 39820
    seq. 0x0db7e410 ack 0x8c66e435
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x02b3
```

### Diagram

![Pod connecting to pod on the same node][pod-to-pod-on-the-same-node-diagram]

## Pod to Pod on another node

### Request

Request sent from a "client" pod with the source address `clientIP:clientPort` destined
to `serverIP:serverPort` of another "server" pod from a different node:

1. Request arrives from client to VPP through the same path as for the [request between pods on the same node](#pod-to-pod-on-the-same-node),
   traversing through the `Reflective ACL` and no-op `nat44-out2in` (steps 1.-6.).
2. Destination IP address `serverIP` matches static route installed by `remoteCNIserver.routeToOtherHostPods()`,
   forwarding the packet via the opposite side of the VXLAN tunnel between this and the destination
   node. All VXLAN interfaces are inside a single bridge domain (BD ID=1), which the packet
   is scheduled to enter through BVI `loop0`.
3. Before the packet gets sent into the bridge-domain with VXLANs, (egress) `Global ACL`
   is applied inside the VPP node `acl-plugin-out-ip4-fa`, confronting the connection
   parameters with the **egress policies of the client's pod** (if there are any).
   The connection is allowed if client's egress policies permit connections
   destined to `serverIP:serverPort`. 
4. The packet enters BD `ID=1` via BVI `loop0`.
5. Ingress `Reflective ACL` for `loop0` allows and reflects the connection.
6. Static ARP entry installed by `remoteCNIserver.vxlanArpEntry()` for every other node
   tells VPP which VXLAN tunnel the packet should travel through to meet the IP address
   selected by the route in the step 2. at the other end.
7. Static L2 FIB entry installed by `remoteCNIserver.vxlanFibEntry()` maps the IP
   address of the VXLAN tunnel's opposite side with the corresponding MAC address.
   This prevents from ARP flooding between nodes.
8. The packet is encapsulated by the VXLAN interface (node `vxlan4-encap`).
   The original packet is carried inside a UDP packet on port 4789 with this node's IP
   as the source and the target node as the destination.
9. The encapsulated packet is routed out via GbE interface.
10. The egress `Global ACL` also assigned to GbE is visited on more time
    (node `acl-plugin-out-ip4-fa`) - the **encapsulated traffic is always permitted**.
11. `nat44-in2out-output`, i.e. NAT in the post-routing phase, applies the identity
    mapping installed for VXLAN to **prevent from source-NATing of the inter-cluster traffic**.
    See [development guide for services][services-dev-guide] for more details
    on NAT identities and integration of services with policies.  
12. **Request arrives via `dpdk-input` to the target node's VPP**.    
13. Ingress `Reflective ACL` for GbeE permits and reflects the connection.
14. `nat44-out2in` NAT node applies identity mapping for VXLAN port - i.e. NAT is
    effectively bypassed while the traffic is still encapsulated.
15. The request enters bridge domain where it gets stripped off the VXLAN header.
16. When leaving the bridge domain, `Reflective ACL` assigned on the ingress
    side of `loop0` permits the connection and creates a free pass for responses.  
17. `nat44-in2out` sees the connection requires no source-NAT to be applied, i.e.
    the packet is not a response from a service.
18. [steps 7.-10. listed for the request between pods on the same node](#pod-to-pod-on-the-same-node)
    are also followed here to deliver the packet into to server's pod.  

Example SYN packet sent from client `10.1.1.12:60996` to server `10.1.2.13:8080`
(captured on both nodes):
```
SYN from the client's node:
---------------------------
04:26:22:973829: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
04:26:22:973852: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:69:99:eb:9d
04:26:22:973856: ip4-input
  TCP: 10.1.1.12 -> 10.1.2.13
    tos 0x00, ttl 64, length 60, checksum 0xf302
    fragment id 0x309f, flags DONT_FRAGMENT
  TCP: 60996 -> 8080
    seq. 0xd26ce551 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x2337
04:26:22:973858: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 7, next index 1, action: 2, match: acl 1 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0c01010a00000000 0000000000000000 0d02010a00000000 000700061f90ee44 0702ffff00000007
   input sw_if_index 7 (lsb16 7) l3 ip4 10.1.1.12 -> 10.1.2.13 l4 proto 6 l4_valid 1 port 60996 -> 8080 tcp flags (valid) 02 rsvd 0
04:26:22:973871: nat44-out2in
  NAT44_OUT2IN: sw_if_index 7, next index 1, session index -1
04:26:22:973878: ip4-lookup
  fib 0 dpo-idx 28 flow hash: 0x00000000
  TCP: 10.1.1.12 -> 10.1.2.13
    tos 0x00, ttl 64, length 60, checksum 0xf302
    fragment id 0x309f, flags DONT_FRAGMENT
  TCP: 60996 -> 8080
    seq. 0xd26ce551 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x2337
04:26:22:973881: ip4-load-balance
  fib 0 dpo-idx 28 flow hash: 0x00000000
  TCP: 10.1.1.12 -> 10.1.2.13
    tos 0x00, ttl 64, length 60, checksum 0xf302
    fragment id 0x309f, flags DONT_FRAGMENT
  TCP: 60996 -> 8080
    seq. 0xd26ce551 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x2337
04:26:22:973883: ip4-rewrite
  tx_sw_if_index 3 dpo-idx 7 : ipv4 via 192.168.30.2 loop0: 1a2b3c4d5e021a2b3c4d5e010800 flow hash: 0x00000000
  00000000: 1a2b3c4d5e021a2b3c4d5e0108004500003c309f40003f06f4020a01010c0a01
  00000020: 020dee441f90d26ce55100000000a002721023370000020405b40402
04:26:22:973884: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 3, next index 1, action: 1, match: acl 2 rule 4 trace_bits 00000000
  pkt info 0000000000000000 0c01010a00000000 0000000000000000 0d02010a00000000 000300061f90ee44 0502ffff00000003
   output sw_if_index 3 (lsb16 3) l3 ip4 10.1.1.12 -> 10.1.2.13 l4 proto 6 l4_valid 1 port 60996 -> 8080 tcp flags (valid) 02 rsvd 0
04:26:22:973888: loop0-output
  loop0
  IP4: 1a:2b:3c:4d:5e:01 -> 1a:2b:3c:4d:5e:02
  TCP: 10.1.1.12 -> 10.1.2.13
    tos 0x00, ttl 63, length 60, checksum 0xf402
    fragment id 0x309f, flags DONT_FRAGMENT
  TCP: 60996 -> 8080
    seq. 0xd26ce551 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x2337
04:26:22:973912: l2-input
  l2-input: sw_if_index 3 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01
04:26:22:973913: l2-input-classify
  l2-classify: sw_if_index 3, table 35, offset 0, next 18
04:26:22:973915: acl-plugin-in-ip4-l2
  acl-plugin: sw_if_index 3, next index 5, action: 2, match: acl 1 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0c01010a00000000 0000000000000000 0d02010a00000000 000300061f90ee44 0702ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.1.12 -> 10.1.2.13 l4 proto 6 l4_valid 1 port 60996 -> 8080 tcp flags (valid) 02 rsvd 0
04:26:22:973918: l2-fwd
  l2-fwd:   sw_if_index 3 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01 bd_index 1
04:26:22:973920: l2-output
  l2-output: sw_if_index 5 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01 data 08 00 45 00 00 3c 30 9f 40 00 3f 06
04:26:22:973921: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 10
04:26:22:973922: ip4-load-balance
  fib 5 dpo-idx 27 flow hash: 0x00000001
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 254, length 110, checksum 0x1b2b
    fragment id 0x0000
  UDP: 50038 -> 4789
    length 90, checksum 0x0000
04:26:22:973923: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 6 : ipv4 via 192.168.16.2 GigabitEthernet0/8/0: 080027a2a45008002772958d0800 flow hash: 0x00000001
  00000000: 080027a2a45008002772958d08004500006e00000000fd111c2bc0a81001c0a8
  00000020: 1002c37612b5005a00000800000000000a001a2b3c4d5e021a2b3c4d
04:26:22:973923: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 1, next index 2, action: 1, match: acl 2 rule 7 trace_bits 00000000
  pkt info 0000000000000000 0110a8c000000000 0000000000000000 0210a8c000000000 0001001112b5c376 0400ffff00000001
   output sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.1 -> 192.168.16.2 l4 proto 17 l4_valid 1 port 50038 -> 4789 tcp flags (invalid) 00 rsvd 0
04:26:22:973924: nat44-in2out-output
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
04:26:22:973926: nat44-in2out-output-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session 0
04:26:22:973932: GigabitEthernet0/8/0-output
  GigabitEthernet0/8/0
  IP4: 08:00:27:72:95:8d -> 08:00:27:a2:a4:50
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50038 -> 4789
    length 90, checksum 0x0000
04:26:22:973932: GigabitEthernet0/8/0-tx
  GigabitEthernet0/8/0 tx queue 0
  buffer 0x1b3cf: current data -50, length 124, free-list 0, clone-count 0, totlen-nifb 0, trace 0x18
                  nated l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 65535, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 78, phys_addr 0x52cf440
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:72:95:8d -> 08:00:27:a2:a4:50
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50038 -> 4789
    length 90, checksum 0x0000

SYN from the server's node:
---------------------------
04:24:37:730732: dpdk-input
  GigabitEthernet0/8/0 rx queue 0
  buffer 0x415e: current data 14, length 110, free-list 0, clone-count 0, totlen-nifb 0, trace 0x0
                 l4-cksum-computed l4-cksum-correct l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 0, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 128, phys_addr 0x19d05800
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:72:95:8d -> 08:00:27:a2:a4:50
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50038 -> 4789
    length 90, checksum 0x0000
04:24:37:730758: ip4-input
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50038 -> 4789
    length 90, checksum 0x0000
04:24:37:730761: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 1, next index 1, action: 2, match: acl 0 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0110a8c000000000 0000000000000000 0210a8c000000000 0001001112b5c376 0600ffff00000001
   input sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.1 -> 192.168.16.2 l4 proto 17 l4_valid 1 port 50038 -> 4789 tcp flags (invalid) 00 rsvd 0
04:24:37:730768: nat44-out2in
  NAT44_OUT2IN: sw_if_index 1, next index 1, session index 7
04:24:37:730771: ip4-lookup
  fib 0 dpo-idx 6 flow hash: 0x00000000
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50038 -> 4789
    length 90, checksum 0x0000
04:24:37:730773: ip4-local
    UDP: 192.168.16.1 -> 192.168.16.2
      tos 0x00, ttl 253, length 110, checksum 0x1c2b
      fragment id 0x0000
    UDP: 50038 -> 4789
      length 90, checksum 0x0000
04:24:37:730775: ip4-udp-lookup
  UDP: src-port 50038 dst-port 4789
04:24:37:730776: vxlan4-input
  VXLAN decap from vxlan_tunnel0 vni 10 next 1 error 0
04:24:37:730778: l2-input
  l2-input: sw_if_index 4 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01
04:24:37:730781: l2-fwd
  l2-fwd:   sw_if_index 4 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01 bd_index 1
04:24:37:730782: ip4-input
  TCP: 10.1.1.12 -> 10.1.2.13
    tos 0x00, ttl 63, length 60, checksum 0xf402
    fragment id 0x309f, flags DONT_FRAGMENT
  TCP: 60996 -> 8080
    seq. 0xd26ce551 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x2337
04:24:37:730782: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 3, next index 2, action: 2, match: acl 0 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0c01010a00000000 0000000000000000 0d02010a00000000 000300061f90ee44 0702ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.1.12 -> 10.1.2.13 l4 proto 6 l4_valid 1 port 60996 -> 8080 tcp flags (valid) 02 rsvd 0
04:24:37:730785: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
04:24:37:730785: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session -1
04:24:37:730787: ip4-lookup
  fib 0 dpo-idx 11 flow hash: 0x00000000
  TCP: 10.1.1.12 -> 10.1.2.13
    tos 0x00, ttl 63, length 60, checksum 0xf402
    fragment id 0x309f, flags DONT_FRAGMENT
  TCP: 60996 -> 8080
    seq. 0xd26ce551 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x2337
04:24:37:730788: ip4-rewrite
  tx_sw_if_index 9 dpo-idx 11 : ipv4 via 10.1.2.13 tap12: 00000000000202fe4784045d0800 flow hash: 0x00000000
  00000000: 00000000000202fe4784045d08004500003c309f40003e06f5020a01010c0a01
  00000020: 020dee441f90d26ce55100000000a002721023370000020405b40402
04:24:37:730791: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 9, next index 1, action: 1, match: acl 1 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0c01010a00000000 0000000000000000 0d02010a00000000 000900061f90ee44 0502ffff00000009
   output sw_if_index 9 (lsb16 9) l3 ip4 10.1.1.12 -> 10.1.2.13 l4 proto 6 l4_valid 1 port 60996 -> 8080 tcp flags (valid) 02 rsvd 0
04:24:37:730794: tap12-output
  tap12
  IP4: 02:fe:47:84:04:5d -> 00:00:00:00:00:02
  TCP: 10.1.1.12 -> 10.1.2.13
    tos 0x00, ttl 62, length 60, checksum 0xf502
    fragment id 0x309f, flags DONT_FRAGMENT
  TCP: 60996 -> 8080
    seq. 0xd26ce551 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x2337
```

### Response

Response sent from the pod with the server application `serverIP:serverPort` back
to the client `clientIP:clientPort` on a different node:

1. Response arrives to VPP through the same path as for the [response between pods on the same node](#pod-to-pod-on-the-same-node),
   traversing through the `Reflective ACL` and no-op `nat44-in2out` (steps 1.-3.).
2. Destination IP address `clientIP` matches static route installed by `remoteCNIserver.routeToOtherHostPods()`,
   forwarding the packet via the opposite side of the VXLAN tunnel between this and the destination
   node. All VXLAN interfaces are inside a single bridge domain (BD ID=1), which the packet
   is scheduled to enter through BVI `loop0`.
3. Before the packet gets sent into the bridge-domain with VXLANs, (egress) `Global ACL`
   is applied inside the VPP node `acl-plugin-out-ip4-fa`. The `Reflective ACL` also
   assigned to `loop0` has already created a free pass for all responses in the connection
   (step 16. for the Request), thus the `Global ACL` is ignored.
4. The packet enters BD `ID=1` via BVI `loop0`.
5. Ingress `Reflective ACL` for `loop0` has no effect in this case - the connection
   was already allowed in the direction of the request.   
6. Steps 6.-12. of the request are also followed here to deliver the packet VXLAN-encapsulated
   to the opposite node.
7. On the client's node, ingress `Reflective ACL` for GbeE has no effect - the connection
   was already allowed in the direction of the request.
8. `nat44-out2in` NAT node applies identity mapping for VXLAN port - i.e. NAT is
   effectively bypassed while the traffic is still encapsulated.
9. When leaving the bridge domain, `Reflective ACL` assigned on the ingress
   side of `loop0` is once again applied with no effect.  
10. `nat44-in2out` sees the packet requires no source-NAT to be applied, i.e.
    the packet is not a response from a service.
11. [steps 4.-7. listed for the response between pods on the same node](#pod-to-pod-on-the-same-node)
    are also followed here to deliver the packet into to client's pod.  

Example SYN-ACK packet sent from server `10.1.2.13:8080` back to the client `10.1.1.12:60996`:
```
SYN-ACK from the server's node:
-------------------------------
04:24:37:730858: virtio-input
  virtio: hw_if_index 9 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
04:24:37:730861: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:47:84:04:5d
04:24:37:730863: ip4-input
  TCP: 10.1.2.13 -> 10.1.1.12
    tos 0x00, ttl 64, length 60, checksum 0x23a2
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 60996
    seq. 0xc363cef4 ack 0xd26ce552
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xa2c2
04:24:37:730864: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 9, next index 2, action: 2, match: acl 0 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0d02010a00000000 0000000000000000 0c01010a00000000 00090006ee441f90 0712ffff00000009
   input sw_if_index 9 (lsb16 9) l3 ip4 10.1.2.13 -> 10.1.1.12 l4 proto 6 l4_valid 1 port 8080 -> 60996 tcp flags (valid) 12 rsvd 0
04:24:37:730866: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 9, next index 3, session -1
04:24:37:730867: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 9, next index 0, session -1
04:24:37:730868: ip4-lookup
  fib 0 dpo-idx 25 flow hash: 0x00000000
  TCP: 10.1.2.13 -> 10.1.1.12
    tos 0x00, ttl 64, length 60, checksum 0x23a2
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 60996
    seq. 0xc363cef4 ack 0xd26ce552
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xa2c2
04:24:37:730869: ip4-load-balance
  fib 0 dpo-idx 25 flow hash: 0x00000000
  TCP: 10.1.2.13 -> 10.1.1.12
    tos 0x00, ttl 64, length 60, checksum 0x23a2
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 60996
    seq. 0xc363cef4 ack 0xd26ce552
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xa2c2
04:24:37:730869: ip4-rewrite
  tx_sw_if_index 3 dpo-idx 6 : ipv4 via 192.168.30.1 loop0: 1a2b3c4d5e011a2b3c4d5e020800 flow hash: 0x00000000
  00000000: 1a2b3c4d5e011a2b3c4d5e0208004500003c000040003f0624a20a01020d0a01
  00000020: 010c1f90ee44c363cef4d26ce552a0127120a2c20000020405b40402
04:24:37:730870: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 3, next index 1, action: 3, match: acl -1 rule 5 trace_bits 80000000
  pkt info 0000000000000000 0d02010a00000000 0000000000000000 0c01010a00000000 00030006ee441f90 0512ffff00000003
   output sw_if_index 3 (lsb16 3) l3 ip4 10.1.2.13 -> 10.1.1.12 l4 proto 6 l4_valid 1 port 8080 -> 60996 tcp flags (valid) 12 rsvd 0
04:24:37:730871: loop0-output
  loop0
  IP4: 1a:2b:3c:4d:5e:02 -> 1a:2b:3c:4d:5e:01
  TCP: 10.1.2.13 -> 10.1.1.12
    tos 0x00, ttl 63, length 60, checksum 0x24a2
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 60996
    seq. 0xc363cef4 ack 0xd26ce552
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xa2c2
04:24:37:730871: l2-input
  l2-input: sw_if_index 3 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02
04:24:37:730872: l2-input-classify
  l2-classify: sw_if_index 3, table 39, offset 0, next 18
04:24:37:730873: acl-plugin-in-ip4-l2
  acl-plugin: sw_if_index 3, next index 5, action: 2, match: acl 0 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0d02010a00000000 0000000000000000 0c01010a00000000 00030006ee441f90 0712ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.2.13 -> 10.1.1.12 l4 proto 6 l4_valid 1 port 8080 -> 60996 tcp flags (valid) 12 rsvd 0
04:24:37:730875: l2-fwd
  l2-fwd:   sw_if_index 3 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 bd_index 1
04:24:37:730875: l2-output
  l2-output: sw_if_index 4 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 data 08 00 45 00 00 3c 00 00 40 00 3f 06
04:24:37:730877: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 10
04:24:37:730877: ip4-load-balance
  fib 4 dpo-idx 24 flow hash: 0x00000001
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 254, length 110, checksum 0x1b2b
    fragment id 0x0000
  UDP: 50493 -> 4789
    length 90, checksum 0x0000
04:24:37:730878: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 5 : ipv4 via 192.168.16.1 GigabitEthernet0/8/0: 08002772958d080027a2a4500800 flow hash: 0x00000001
  00000000: 08002772958d080027a2a45008004500006e00000000fd111c2bc0a81002c0a8
  00000020: 1001c53d12b5005a00000800000000000a001a2b3c4d5e011a2b3c4d
04:24:37:730878: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 1, next index 2, action: 1, match: acl 3 rule 7 trace_bits 00000000
  pkt info 0000000000000000 0210a8c000000000 0000000000000000 0110a8c000000000 0001001112b5c53d 0400ffff00000001
   output sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.2 -> 192.168.16.1 l4 proto 17 l4_valid 1 port 50493 -> 4789 tcp flags (invalid) 00 rsvd 0
04:24:37:730879: nat44-in2out-output
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
04:24:37:730880: nat44-in2out-output-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session 0
04:24:37:730885: GigabitEthernet0/8/0-output
  GigabitEthernet0/8/0
  IP4: 08:00:27:a2:a4:50 -> 08:00:27:72:95:8d
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50493 -> 4789
    length 90, checksum 0x0000
04:24:37:730885: GigabitEthernet0/8/0-tx
  GigabitEthernet0/8/0 tx queue 0
  buffer 0x2446a: current data -50, length 124, free-list 0, clone-count 0, totlen-nifb 0, trace 0x1
                  nated l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 65535, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 78, phys_addr 0x19511b00
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:a2:a4:50 -> 08:00:27:72:95:8d
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50493 -> 4789
    length 90, checksum 0x0000


SYN-ACK from the client's node:
-------------------------------
04:26:22:974150: dpdk-input
  GigabitEthernet0/8/0 rx queue 0
  buffer 0x4332: current data 14, length 110, free-list 0, clone-count 0, totlen-nifb 0, trace 0x19
                 l4-cksum-computed l4-cksum-correct l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 0, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 128, phys_addr 0x5b0cd00
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:a2:a4:50 -> 08:00:27:72:95:8d
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50493 -> 4789
    length 90, checksum 0x0000
04:26:22:974172: ip4-input
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50493 -> 4789
    length 90, checksum 0x0000
04:26:22:974174: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 1, next index 1, action: 2, match: acl 1 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0210a8c000000000 0000000000000000 0110a8c000000000 0001001112b5c53d 0600ffff00000001
   input sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.2 -> 192.168.16.1 l4 proto 17 l4_valid 1 port 50493 -> 4789 tcp flags (invalid) 00 rsvd 0
04:26:22:974175: nat44-out2in
  NAT44_OUT2IN: sw_if_index 1, next index 1, session index 1
04:26:22:974176: ip4-lookup
  fib 0 dpo-idx 6 flow hash: 0x00000000
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 50493 -> 4789
    length 90, checksum 0x0000
04:26:22:974177: ip4-local
    UDP: 192.168.16.2 -> 192.168.16.1
      tos 0x00, ttl 253, length 110, checksum 0x1c2b
      fragment id 0x0000
    UDP: 50493 -> 4789
      length 90, checksum 0x0000
04:26:22:974179: ip4-udp-lookup
  UDP: src-port 50493 dst-port 4789
04:26:22:974180: vxlan4-input
  VXLAN decap from vxlan_tunnel0 vni 10 next 1 error 0
04:26:22:974181: l2-input
  l2-input: sw_if_index 5 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02
04:26:22:974182: l2-fwd
  l2-fwd:   sw_if_index 5 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 bd_index 1
04:26:22:974183: ip4-input
  TCP: 10.1.2.13 -> 10.1.1.12
    tos 0x00, ttl 63, length 60, checksum 0x24a2
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 60996
    seq. 0xc363cef4 ack 0xd26ce552
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xa2c2
04:26:22:974183: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 3, next index 2, action: 2, match: acl 1 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0d02010a00000000 0000000000000000 0c01010a00000000 00030006ee441f90 0712ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.2.13 -> 10.1.1.12 l4 proto 6 l4_valid 1 port 8080 -> 60996 tcp flags (valid) 12 rsvd 0
04:26:22:974184: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
04:26:22:974185: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session -1
04:26:22:974187: ip4-lookup
  fib 0 dpo-idx 9 flow hash: 0x00000000
  TCP: 10.1.2.13 -> 10.1.1.12
    tos 0x00, ttl 63, length 60, checksum 0x24a2
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 60996
    seq. 0xc363cef4 ack 0xd26ce552
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xa2c2
04:26:22:974188: ip4-rewrite
  tx_sw_if_index 7 dpo-idx 9 : ipv4 via 10.1.1.12 tap11: 00000000000202fe6999eb9d0800 flow hash: 0x00000000
  00000000: 00000000000202fe6999eb9d08004500003c000040003e0625a20a01020d0a01
  00000020: 010c1f90ee44c363cef4d26ce552a0127120a2c20000020405b40402
04:26:22:974189: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 7, next index 1, action: 3, match: acl -1 rule 177 trace_bits 80000000
  pkt info 0000000000000000 0d02010a00000000 0000000000000000 0c01010a00000000 00070006ee441f90 0512ffff00000007
   output sw_if_index 7 (lsb16 7) l3 ip4 10.1.2.13 -> 10.1.1.12 l4 proto 6 l4_valid 1 port 8080 -> 60996 tcp flags (valid) 12 rsvd 0
04:26:22:974190: tap11-output
  tap11
  IP4: 02:fe:69:99:eb:9d -> 00:00:00:00:00:02
  TCP: 10.1.2.13 -> 10.1.1.12
    tos 0x00, ttl 62, length 60, checksum 0x25a2
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 60996
    seq. 0xc363cef4 ack 0xd26ce552
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xa2c2
```

### Diagram

![Pod connecting to pod on another node][pod-to-pod-on-another-node-diagram]

## Pod to Pod in the host network stack

### Request

Request sent from a "client" pod with the source address `clientIP:clientPort` destined
to "server" `serverIP:serverPort` inside the host network stack of the same node:

1. Request arrives from client to VPP through the same path as for the [request between pods on the same node](#pod-to-pod-on-the-same-node),
   traversing through the `Reflective ACL` and no-op `nat44-out2in` (steps 1.-6.).
2. Since the server is inside the host network stack, the IP address it has assigned
   is one from the host interfaces. `remoteCNIserver.routesToHost()` configures
   one static route to VPP for every interface in the host stack to go via `tap0`,
   connecting VPP with the host.
3. Before the packet gets sent into the host via `tap0`, (egress) `Global ACL`
   is applied inside the VPP node `acl-plugin-out-ip4-fa`, confronting the connection
   parameters with the **egress policies of the client's pod** (if there are any).
   The connection is allowed if client's egress policies permit connections
   destined to `serverIP:serverPort`.
   Note: ingress policies assigned to the server are ignored - Contiv/VPP does not support
         policies for pods inside the host network stack. 
4. `tap0` is the only interface in VPP with no static ARPs configured. The hardware
   address of the TAP's host side (`vpp1`) is discovered dynamically using a broadcast
   ARP request.  
5. Request arrives to the host network stack.    
 
Example SYN packet sent from client `10.1.1.3:54252` to server `10.20.0.2:8080`:
```
01:00:22:301693: virtio-input
  virtio: hw_if_index 6 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:00:22:301716: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:16:3f:5f:0f
01:00:22:301721: ip4-input
  TCP: 10.1.1.3 -> 10.20.0.2
    tos 0x00, ttl 64, length 60, checksum 0x8af6
    fragment id 0x9aac, flags DONT_FRAGMENT
  TCP: 54252 -> 8080
    seq. 0x66e00e6d ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xc33d
01:00:22:301724: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 6, next index 2, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0200140a00000000 000600061f90d3ec 0702ffff00000006
   input sw_if_index 6 (lsb16 6) l3 ip4 10.1.1.3 -> 10.20.0.2 l4 proto 6 l4_valid 1 port 54252 -> 8080 tcp flags (valid) 02 rsvd 0
01:00:22:301825: nat44-out2in
  NAT44_OUT2IN: sw_if_index 6, next index 1, session index -1
01:00:22:301832: ip4-lookup
  fib 0 dpo-idx 3 flow hash: 0x00000000
  TCP: 10.1.1.3 -> 10.20.0.2
    tos 0x00, ttl 64, length 60, checksum 0x8af6
    fragment id 0x9aac, flags DONT_FRAGMENT
  TCP: 54252 -> 8080
    seq. 0x66e00e6d ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xc33d
01:00:22:301835: ip4-rewrite
  tx_sw_if_index 2 dpo-idx 3 : ipv4 via 172.30.1.2 tap0: 3e1b702d4d510123456789420800 flow hash: 0x00000000
  00000000: 3e1b702d4d5101234567894208004500003c9aac40003f068bf60a0101030a14
  00000020: 0002d3ec1f9066e00e6d00000000a0027210c33d0000020405b40402
01:00:22:301836: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 2, next index 1, action: 1, match: acl 2 rule 6 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0200140a00000000 000200061f90d3ec 0502ffff00000002
   output sw_if_index 2 (lsb16 2) l3 ip4 10.1.1.3 -> 10.20.0.2 l4 proto 6 l4_valid 1 port 54252 -> 8080 tcp flags (valid) 02 rsvd 0
01:00:22:301839: tap0-output
  tap0
  IP4: 01:23:45:67:89:42 -> 3e:1b:70:2d:4d:51
  TCP: 10.1.1.3 -> 10.20.0.2
    tos 0x00, ttl 63, length 60, checksum 0x8bf6
    fragment id 0x9aac, flags DONT_FRAGMENT
  TCP: 54252 -> 8080
    seq. 0x66e00e6d ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xc33d
```

### Response

Response sent from the pod with the server application `serverIP:serverPort`, running
in the host network stack, back to the client `clientIP:clientPort` inside its own
network namespace on the same node:

1. Static route installed by `remoteCNIserver.routePODsFromHost()` on every node's host
   stack sends traffic destined to any address from `PodSubnetCIDR` (including `clientIP`)
   via `vpp1` - host's side of the TAP interface connecting VPP with the host (`tap0` is the VPP side).
2. Host stack determines physical address of `tap0` dynamically, i.e. no static ARP
   configured.
3. `Reflective ACL` assigned to `tap0` is taken with no effect - connection was already
   allowed in the direction of the request.
4. `nat44-in2out` node checks if the source address should be translated as local IP
   into an external IP using any of the static mappings installed
   by the [service plugin][services-dev-guid] - in this case the server was accessed
   directly, not via service VIP, thus **no translation occurs**
   (`session -1` in the packet trace).
5. [steps 4.-7. listed for the response between pods on the same node](#pod-to-pod-on-the-same-node)
   are also followed here to deliver the packet into to client's pod. 
    
Example SYN-ACK packet sent from server `10.20.0.2:8080` back to client `10.1.1.3:54252`:
```
01:00:22:302975: virtio-input
  virtio: hw_if_index 2 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:00:22:302981: ethernet-input
  IP4: 3e:1b:70:2d:4d:51 -> 01:23:45:67:89:42
01:00:22:302989: ip4-input
  TCP: 10.20.0.2 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x25a3
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 54252
    seq. 0x7e79850b ack 0x66e00e6e
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x2bc9
01:00:22:302991: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 2, next index 1, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0200140a00000000 0000000000000000 0301010a00000000 00020006d3ec1f90 0712ffff00000002
   input sw_if_index 2 (lsb16 2) l3 ip4 10.20.0.2 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 54252 tcp flags (valid) 12 rsvd 0
01:00:22:303001: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 2, next index 3, session -1
01:00:22:303003: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 2, next index 0, session -1
01:00:22:303005: ip4-lookup
  fib 0 dpo-idx 8 flow hash: 0x00000000
  TCP: 10.20.0.2 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x25a3
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 54252
    seq. 0x7e79850b ack 0x66e00e6e
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x2bc9
01:00:22:303007: ip4-rewrite
  tx_sw_if_index 6 dpo-idx 8 : ipv4 via 10.1.1.3 tap2: 00000000000202fe163f5f0f0800 flow hash: 0x00000000
  00000000: 00000000000202fe163f5f0f08004500003c000040003f0626a30a1400020a01
  00000020: 01031f90d3ec7e79850b66e00e6ea01271202bc90000020405b40402
01:00:22:303009: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 6, next index 1, action: 3, match: acl -1 rule 100 trace_bits 80000000
  pkt info 0000000000000000 0200140a00000000 0000000000000000 0301010a00000000 00060006d3ec1f90 0512ffff00000006
   output sw_if_index 6 (lsb16 6) l3 ip4 10.20.0.2 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 54252 tcp flags (valid) 12 rsvd 0
01:00:22:303013: tap2-output
  tap2
  IP4: 02:fe:16:3f:5f:0f -> 00:00:00:00:00:02
  TCP: 10.20.0.2 -> 10.1.1.3
    tos 0x00, ttl 63, length 60, checksum 0x26a3
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 54252
    seq. 0x7e79850b ack 0x66e00e6e
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x2bc9
```

### Diagram

TODO

## Host to Pod

### Request

Request sent from the host with the source address `hostIP:hostPort` destined
to a "server" pod `serverIP:serverPort` on the same node:

1. Static route installed by `remoteCNIserver.routePODsFromHost()` on every node's host
   stack sends traffic destined to any address from `PodSubnetCIDR` (including `serverIP`)
   via `vpp1` - host's side of the TAP interface connecting VPP with the host
   (`tap0` is the VPP side).
2. Host stack determines physical address of `tap0` dynamically, i.e. no static ARP
   configured.
3. `Reflective ACL` assigned to `tap0` **allows and reflects the connection**.
4. `nat44-in2out` node checks if the source address should be translated as local IP
   into an external IP using any of the static mappings installed
   by the [service plugin][services-dev-guid] - but this is not a response from a service VIP,
   thus **no translation occurs**  (`session -1` in the packet trace).
5. [steps 7.-10. listed for the request between pods on the same node](#pod-to-pod-on-the-same-node)
   are also followed here to deliver the packet into to server's pod.
   
Example SYN packet sent from the host `172.30.1.2:32966` to server `10.1.1.6:8080`:
```
01:36:39:413621: virtio-input
  virtio: hw_if_index 2 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:36:39:413625: ethernet-input
  IP4: 3e:1b:70:2d:4d:51 -> 01:23:45:67:89:42
01:36:39:413629: ip4-input
  TCP: 172.30.1.2 -> 10.1.1.6
    tos 0x00, ttl 64, length 60, checksum 0xe443
    fragment id 0x9e51, flags DONT_FRAGMENT
  TCP: 32966 -> 8080
    seq. 0xe2697e8e ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x3b85
01:36:39:413631: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 2, next index 1, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 02011eac00000000 0000000000000000 0601010a00000000 000200061f9080c6 0702ffff00000002
   input sw_if_index 2 (lsb16 2) l3 ip4 172.30.1.2 -> 10.1.1.6 l4 proto 6 l4_valid 1 port 32966 -> 8080 tcp flags (valid) 02 rsvd 0
01:36:39:413637: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 2, next index 3, session -1
01:36:39:413639: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 2, next index 0, session -1
01:36:39:413641: ip4-lookup
  fib 0 dpo-idx 11 flow hash: 0x00000000
  TCP: 172.30.1.2 -> 10.1.1.6
    tos 0x00, ttl 64, length 60, checksum 0xe443
    fragment id 0x9e51, flags DONT_FRAGMENT
  TCP: 32966 -> 8080
    seq. 0xe2697e8e ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x3b85
01:36:39:413643: ip4-rewrite
  tx_sw_if_index 9 dpo-idx 11 : ipv4 via 10.1.1.6 tap5: 00000000000202fe0407d1e20800 flow hash: 0x00000000
  00000000: 00000000000202fe0407d1e208004500003c9e5140003f06e543ac1e01020a01
  00000020: 010680c61f90e2697e8e00000000a00272103b850000020405b40402
01:36:39:413645: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 9, next index 1, action: 1, match: acl 4 rule 3 trace_bits 00000000
  pkt info 0000000000000000 02011eac00000000 0000000000000000 0601010a00000000 000900061f9080c6 0502ffff00000009
   output sw_if_index 9 (lsb16 9) l3 ip4 172.30.1.2 -> 10.1.1.6 l4 proto 6 l4_valid 1 port 32966 -> 8080 tcp flags (valid) 02 rsvd 0
01:36:39:413649: tap5-output
  tap5
  IP4: 02:fe:04:07:d1:e2 -> 00:00:00:00:00:02
  TCP: 172.30.1.2 -> 10.1.1.6
    tos 0x00, ttl 63, length 60, checksum 0xe543
    fragment id 0x9e51, flags DONT_FRAGMENT
  TCP: 32966 -> 8080
    seq. 0xe2697e8e ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x3b85
```

### Response

Response sent from the pod with the server application `serverIP:serverPort`
back to the host `hostIP:hostPort` on the same node:

1. Response arrives to VPP through the same path as for the [response between pods on the same node](#pod-to-pod-on-the-same-node),
   traversing through the `Reflective ACL` and no-op `nat44-in2out` (steps 1.-3.).
2. `remoteCNIserver.routesToHost()` configures one static route to VPP for every
   interface in the host stack (including `hostIP`) to go via `tap0`, connecting
   VPP with the host.
3. Before the response gets sent back into the host via `tap0`, (egress) `Global ACL`
   is applied inside the VPP node `acl-plugin-out-ip4-fa`. The connection was already
   permitted and reflected by the `Reflective ACL` assigned to `tap0`, hence
   the `Global ACL` is bypassed.
4. `tap0` is the only interface in VPP with no static ARPs configured. The hardware
   address of the TAP's host side (`vpp1`) is discovered dynamically using a broadcast
   ARP request.  
5. Response arrives to the host network stack.    

Example SYN-ACK packet sent from server `10.1.1.6:8080` back to the host `172.30.1.2:32966`:
```
virtio: hw_if_index 9 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:36:39:413690: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:04:07:d1:e2
01:36:39:413692: ip4-input
  TCP: 10.1.1.6 -> 172.30.1.2
    tos 0x00, ttl 64, length 60, checksum 0x8295
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 32966
    seq. 0xf14b9572 ack 0xe2697e8f
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xd4b0
01:36:39:413694: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 9, next index 1, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0601010a00000000 0000000000000000 02011eac00000000 0009000680c61f90 0712ffff00000009
   input sw_if_index 9 (lsb16 9) l3 ip4 10.1.1.6 -> 172.30.1.2 l4 proto 6 l4_valid 1 port 8080 -> 32966 tcp flags (valid) 12 rsvd 0
01:36:39:413697: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 9, next index 3, session -1
01:36:39:413698: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 9, next index 0, session -1
01:36:39:413699: ip4-lookup
  fib 0 dpo-idx 3 flow hash: 0x00000000
  TCP: 10.1.1.6 -> 172.30.1.2
    tos 0x00, ttl 64, length 60, checksum 0x8295
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 32966
    seq. 0xf14b9572 ack 0xe2697e8f
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xd4b0
01:36:39:413701: ip4-rewrite
  tx_sw_if_index 2 dpo-idx 3 : ipv4 via 172.30.1.2 tap0: 3e1b702d4d510123456789420800 flow hash: 0x00000000
  00000000: 3e1b702d4d5101234567894208004500003c000040003f0683950a010106ac1e
  00000020: 01021f9080c6f14b9572e2697e8fa0127120d4b00000020405b40402
01:36:39:413701: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 2, next index 1, action: 3, match: acl -1 rule 22 trace_bits 80000000
  pkt info 0000000000000000 0601010a00000000 0000000000000000 02011eac00000000 0002000680c61f90 0512ffff00000002
   output sw_if_index 2 (lsb16 2) l3 ip4 10.1.1.6 -> 172.30.1.2 l4 proto 6 l4_valid 1 port 8080 -> 32966 tcp flags (valid) 12 rsvd 0
01:36:39:413703: tap0-output
  tap0
  IP4: 01:23:45:67:89:42 -> 3e:1b:70:2d:4d:51
  TCP: 10.1.1.6 -> 172.30.1.2
    tos 0x00, ttl 63, length 60, checksum 0x8395
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 32966
    seq. 0xf14b9572 ack 0xe2697e8f
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xd4b0
```

### Diagram

TODO (minor difference with "Pod to Pod in the host network stack")

## Pod To Internet

### Request

TODO

### Response

TODO

### Diagram

TODO

## Pod to Service with chosen backend on the same node

### Request

For request sent from a "client" pod with the source address `clientIP:clientPort`
destined to service `serviceIP:servicePort`, load-balanced to the endpoint
`serverIP:serverPort` on the same node:

 - the same steps are taken as for [request between pods on the same node](#pod-to-pod-on-the-same-node),
   except in the 6th step `nat44-out2in` translates destination address `serviceIP:servicePort`
   to randomly chosen endpoint `serverIP:serverPort` (session index is not -1 in the packet trace)

Example SYN packet sent from client `10.1.1.3:51082` to service `10.104.221.85:80`,
load-balanced to endpoint `10.1.1.5:8080`:
```
01:59:50:724476: virtio-input
  virtio: hw_if_index 6 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:59:50:724483: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:16:3f:5f:0f
01:59:50:724487: ip4-input
  TCP: 10.1.1.3 -> 10.104.221.85
    tos 0x00, ttl 64, length 60, checksum 0x8804
    fragment id 0xbff6, flags DONT_FRAGMENT
  TCP: 51082 -> 80
    seq. 0x0a8891a7 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x50b8
01:59:50:724489: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 6, next index 2, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 55dd680a00000000 000600060050c78a 0702ffff00000006
   input sw_if_index 6 (lsb16 6) l3 ip4 10.1.1.3 -> 10.104.221.85 l4 proto 6 l4_valid 1 port 51082 -> 80 tcp flags (valid) 02 rsvd 0
01:59:50:724497: nat44-out2in
  NAT44_OUT2IN: sw_if_index 6, next index 1, session index 5
01:59:50:724509: ip4-lookup
  fib 0 dpo-idx 10 flow hash: 0x00000000
  TCP: 10.1.1.3 -> 10.1.1.5
    tos 0x00, ttl 64, length 60, checksum 0x64bc
    fragment id 0xbff6, flags DONT_FRAGMENT
  TCP: 51082 -> 8080
    seq. 0x0a8891a7 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x0e30
01:59:50:724511: ip4-rewrite
  tx_sw_if_index 8 dpo-idx 10 : ipv4 via 10.1.1.5 tap4: 00000000000202fe10037c4d0800 flow hash: 0x00000000
  00000000: 00000000000202fe10037c4d08004500003cbff640003f0665bc0a0101030a01
  00000020: 0105c78a1f900a8891a700000000a00272100e300000020405b40402
01:59:50:724513: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 8, next index 1, action: 1, match: acl 4 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0501010a00000000 000800061f90c78a 0502ffff00000008
   output sw_if_index 8 (lsb16 8) l3 ip4 10.1.1.3 -> 10.1.1.5 l4 proto 6 l4_valid 1 port 51082 -> 8080 tcp flags (valid) 02 rsvd 0
01:59:50:724518: tap4-output
  tap4
  IP4: 02:fe:10:03:7c:4d -> 00:00:00:00:00:02
  TCP: 10.1.1.3 -> 10.1.1.5
    tos 0x00, ttl 63, length 60, checksum 0x65bc
    fragment id 0xbff6, flags DONT_FRAGMENT
  TCP: 51082 -> 8080
    seq. 0x0a8891a7 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x0e30
```

### Response

For response sent from server `serverIP:serverPort`, acting as endpoint for service
`serviceIP:servicePort`, back to the client `clientIP:clientPort`:

 - the same steps are taken as for [response between pods on the same node](#pod-to-pod-on-the-same-node),
   except that in the 3th step `nat44-in2out` translates the source address `serverIP:serverPort`
   back to service VIP `serviceIP:servicePort` (session is not -1 in the packet trace)

Example SYN-ACK packet sent from server `10.1.1.5:8080`, acting as endpoint of service
`10.104.221.85:80`, back to client `10.1.1.3:51082`:
```
01:59:50:724579: virtio-input
  virtio: hw_if_index 8 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
01:59:50:724725: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:10:03:7c:4d
01:59:50:724728: ip4-input
  TCP: 10.1.1.5 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x24b3
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 51082
    seq. 0xa80cb872 ack 0x0a8891a8
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x8023
01:59:50:724729: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 8, next index 1, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0501010a00000000 0000000000000000 0301010a00000000 00080006c78a1f90 0712ffff00000008
   input sw_if_index 8 (lsb16 8) l3 ip4 10.1.1.5 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 51082 tcp flags (valid) 12 rsvd 0
01:59:50:724733: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 8, next index 3, session -1
01:59:50:724736: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 8, next index 0, session 5
01:59:50:724737: ip4-lookup
  fib 0 dpo-idx 8 flow hash: 0x00000000
  TCP: 10.104.221.85 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x47fb
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 80 -> 51082
    seq. 0xa80cb872 ack 0x0a8891a8
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xc2ab
01:59:50:724739: ip4-rewrite
  tx_sw_if_index 6 dpo-idx 8 : ipv4 via 10.1.1.3 tap2: 00000000000202fe163f5f0f0800 flow hash: 0x00000000
  00000000: 00000000000202fe163f5f0f08004500003c000040003f0648fb0a68dd550a01
  00000020: 01030050c78aa80cb8720a8891a8a0127120c2ab0000020405b40402
01:59:50:724739: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 6, next index 1, action: 3, match: acl -1 rule 41 trace_bits 80000000
  pkt info 0000000000000000 55dd680a00000000 0000000000000000 0301010a00000000 00060006c78a0050 0512ffff00000006
   output sw_if_index 6 (lsb16 6) l3 ip4 10.104.221.85 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 80 -> 51082 tcp flags (valid) 12 rsvd 0
01:59:50:724740: tap2-output
  tap2
  IP4: 02:fe:16:3f:5f:0f -> 00:00:00:00:00:02
  TCP: 10.104.221.85 -> 10.1.1.3
    tos 0x00, ttl 63, length 60, checksum 0x48fb
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 80 -> 51082
    seq. 0xa80cb872 ack 0x0a8891a8
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xc2ab
```

## Pod to Service with chosen backend on another node

### Request

For request sent from a "client" pod with the source address `clientIP:clientPort`
destined to service `serviceIP:servicePort`, load-balanced to the endpoint
`serverIP:serverPort` from another node:

 - the same steps are taken as for [request between pods on different nodes](#pod-to-pod-on-another-node),
   except that `nat44-out2in` between client's TAP and `loop0` (the first pass through this node)
   translates destination address `serviceIP:servicePort` to randomly chosen
   endpoint `serverIP:serverPort` from another node (session index is not -1
   in the packet trace)

Example SYN packet sent from client `10.1.1.3:49710` to service `10.97.193.160:80`,
load-balanced to endpoint `10.1.2.4:8080` from another node (trace taken from both nodes):
```
SYN from the client's node:
---------------------------
02:26:06:586577: virtio-input
  virtio: hw_if_index 6 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:26:06:586615: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:16:3f:5f:0f
02:26:06:586620: ip4-input
  TCP: 10.1.1.3 -> 10.97.193.160
    tos 0x00, ttl 64, length 60, checksum 0xda5c
    fragment id 0x895a, flags DONT_FRAGMENT
  TCP: 49710 -> 80
    seq. 0x27c7a68b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x3e27
02:26:06:586622: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 6, next index 2, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 a0c1610a00000000 000600060050c22e 0702ffff00000006
   input sw_if_index 6 (lsb16 6) l3 ip4 10.1.1.3 -> 10.97.193.160 l4 proto 6 l4_valid 1 port 49710 -> 80 tcp flags (valid) 02 rsvd 0
02:26:06:586655: nat44-out2in
  NAT44_OUT2IN: sw_if_index 6, next index 1, session index 4
02:26:06:586665: ip4-lookup
  fib 0 dpo-idx 28 flow hash: 0x00000000
  TCP: 10.1.1.3 -> 10.1.2.4
    tos 0x00, ttl 64, length 60, checksum 0x9a59
    fragment id 0x895a, flags DONT_FRAGMENT
  TCP: 49710 -> 8080
    seq. 0x27c7a68b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xdee3
02:26:06:586668: ip4-load-balance
  fib 0 dpo-idx 28 flow hash: 0x00000000
  TCP: 10.1.1.3 -> 10.1.2.4
    tos 0x00, ttl 64, length 60, checksum 0x9a59
    fragment id 0x895a, flags DONT_FRAGMENT
  TCP: 49710 -> 8080
    seq. 0x27c7a68b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xdee3
02:26:06:586687: ip4-rewrite
  tx_sw_if_index 3 dpo-idx 7 : ipv4 via 192.168.30.2 loop0: 1a2b3c4d5e021a2b3c4d5e010800 flow hash: 0x00000000
  00000000: 1a2b3c4d5e021a2b3c4d5e0108004500003c895a40003f069b590a0101030a01
  00000020: 0204c22e1f9027c7a68b00000000a0027210dee30000020405b40402
02:26:06:586688: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 3, next index 1, action: 1, match: acl 2 rule 4 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0402010a00000000 000300061f90c22e 0502ffff00000003
   output sw_if_index 3 (lsb16 3) l3 ip4 10.1.1.3 -> 10.1.2.4 l4 proto 6 l4_valid 1 port 49710 -> 8080 tcp flags (valid) 02 rsvd 0
02:26:06:586692: loop0-output
  loop0
  IP4: 1a:2b:3c:4d:5e:01 -> 1a:2b:3c:4d:5e:02
  TCP: 10.1.1.3 -> 10.1.2.4
    tos 0x00, ttl 63, length 60, checksum 0x9b59
    fragment id 0x895a, flags DONT_FRAGMENT
  TCP: 49710 -> 8080
    seq. 0x27c7a68b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xdee3
02:26:06:586695: l2-input
  l2-input: sw_if_index 3 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01
02:26:06:586696: l2-input-classify
  l2-classify: sw_if_index 3, table 23, offset 0, next 18
02:26:06:586698: acl-plugin-in-ip4-l2
  acl-plugin: sw_if_index 3, next index 5, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0402010a00000000 000300061f90c22e 0702ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.1.3 -> 10.1.2.4 l4 proto 6 l4_valid 1 port 49710 -> 8080 tcp flags (valid) 02 rsvd 0
02:26:06:586713: l2-fwd
  l2-fwd:   sw_if_index 3 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01 bd_index 1
02:26:06:586715: l2-output
  l2-output: sw_if_index 5 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01 data 08 00 45 00 00 3c 89 5a 40 00 3f 06
02:26:06:586716: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 10
02:26:06:586718: ip4-load-balance
  fib 5 dpo-idx 27 flow hash: 0x00000002
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 254, length 110, checksum 0x1b2b
    fragment id 0x0000
  UDP: 60039 -> 4789
    length 90, checksum 0x0000
02:26:06:586718: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 6 : ipv4 via 192.168.16.2 GigabitEthernet0/8/0: 080027e05749080027449fd80800 flow hash: 0x00000002
  00000000: 080027e05749080027449fd808004500006e00000000fd111c2bc0a81001c0a8
  00000020: 1002ea8712b5005a00000800000000000a001a2b3c4d5e021a2b3c4d
02:26:06:586719: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 1, next index 2, action: 1, match: acl 2 rule 8 trace_bits 00000000
  pkt info 0000000000000000 0110a8c000000000 0000000000000000 0210a8c000000000 0001001112b5ea87 0400ffff00000001
   output sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.1 -> 192.168.16.2 l4 proto 17 l4_valid 1 port 60039 -> 4789 tcp flags (invalid) 00 rsvd 0
02:26:06:586720: nat44-in2out-output
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
02:26:06:586723: nat44-in2out-output-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session 7
02:26:06:586728: GigabitEthernet0/8/0-output
  GigabitEthernet0/8/0
  IP4: 08:00:27:44:9f:d8 -> 08:00:27:e0:57:49
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 60039 -> 4789
    length 90, checksum 0x0000
02:26:06:586729: GigabitEthernet0/8/0-tx
  GigabitEthernet0/8/0 tx queue 0
  buffer 0x17cc8: current data -50, length 124, free-list 0, clone-count 0, totlen-nifb 0, trace 0x18
                  nated l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 65535, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 78, phys_addr 0x6e9f3280
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:44:9f:d8 -> 08:00:27:e0:57:49
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 60039 -> 4789
    length 90, checksum 0x0000

SYN from the server's node:
---------------------------
02:24:27:765594: dpdk-input
  GigabitEthernet0/8/0 rx queue 0
  buffer 0x4a82: current data 14, length 110, free-list 0, clone-count 0, totlen-nifb 0, trace 0x0
                 l4-cksum-computed l4-cksum-correct l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 0, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 128, phys_addr 0x2732a100
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:44:9f:d8 -> 08:00:27:e0:57:49
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 60039 -> 4789
    length 90, checksum 0x0000
02:24:27:765625: ip4-input
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 60039 -> 4789
    length 90, checksum 0x0000
02:24:27:765628: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 1, next index 1, action: 2, match: acl 2 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0110a8c000000000 0000000000000000 0210a8c000000000 0001001112b5ea87 0600ffff00000001
   input sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.1 -> 192.168.16.2 l4 proto 17 l4_valid 1 port 60039 -> 4789 tcp flags (invalid) 00 rsvd 0
02:24:27:765633: nat44-out2in
  NAT44_OUT2IN: sw_if_index 1, next index 1, session index 0
02:24:27:765636: ip4-lookup
  fib 0 dpo-idx 6 flow hash: 0x00000000
  UDP: 192.168.16.1 -> 192.168.16.2
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 60039 -> 4789
    length 90, checksum 0x0000
02:24:27:765638: ip4-local
    UDP: 192.168.16.1 -> 192.168.16.2
      tos 0x00, ttl 253, length 110, checksum 0x1c2b
      fragment id 0x0000
    UDP: 60039 -> 4789
      length 90, checksum 0x0000
02:24:27:765640: ip4-udp-lookup
  UDP: src-port 60039 dst-port 4789
02:24:27:765641: vxlan4-input
  VXLAN decap from vxlan_tunnel0 vni 10 next 1 error 0
02:24:27:765643: l2-input
  l2-input: sw_if_index 4 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01
02:24:27:765645: l2-fwd
  l2-fwd:   sw_if_index 4 dst 1a:2b:3c:4d:5e:02 src 1a:2b:3c:4d:5e:01 bd_index 1
02:24:27:765647: ip4-input
  TCP: 10.1.1.3 -> 10.1.2.4
    tos 0x00, ttl 63, length 60, checksum 0x9b59
    fragment id 0x895a, flags DONT_FRAGMENT
  TCP: 49710 -> 8080
    seq. 0x27c7a68b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xdee3
02:24:27:765647: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 3, next index 2, action: 2, match: acl 2 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0402010a00000000 000300061f90c22e 0702ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.1.3 -> 10.1.2.4 l4 proto 6 l4_valid 1 port 49710 -> 8080 tcp flags (valid) 02 rsvd 0
02:24:27:765649: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
02:24:27:765650: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session -1
02:24:27:765651: ip4-lookup
  fib 0 dpo-idx 9 flow hash: 0x00000000
  TCP: 10.1.1.3 -> 10.1.2.4
    tos 0x00, ttl 63, length 60, checksum 0x9b59
    fragment id 0x895a, flags DONT_FRAGMENT
  TCP: 49710 -> 8080
    seq. 0x27c7a68b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xdee3
02:24:27:765653: ip4-rewrite
  tx_sw_if_index 7 dpo-idx 9 : ipv4 via 10.1.2.4 tap3: 00000000000202fe1d7295660800 flow hash: 0x00000000
  00000000: 00000000000202fe1d72956608004500003c895a40003e069c590a0101030a01
  00000020: 0204c22e1f9027c7a68b00000000a0027210dee30000020405b40402
02:24:27:765654: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 7, next index 1, action: 1, match: acl 4 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0402010a00000000 000700061f90c22e 0502ffff00000007
   output sw_if_index 7 (lsb16 7) l3 ip4 10.1.1.3 -> 10.1.2.4 l4 proto 6 l4_valid 1 port 49710 -> 8080 tcp flags (valid) 02 rsvd 0
02:24:27:765658: tap3-output
  tap3
  IP4: 02:fe:1d:72:95:66 -> 00:00:00:00:00:02
  TCP: 10.1.1.3 -> 10.1.2.4
    tos 0x00, ttl 62, length 60, checksum 0x9c59
    fragment id 0x895a, flags DONT_FRAGMENT
  TCP: 49710 -> 8080
    seq. 0x27c7a68b ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xdee3
```

### Response

For response sent from server `serverIP:serverPort`, acting as endpoint for service
`serviceIP:servicePort`, back to the client `clientIP:clientPort` deployed on another node:

 - the same steps are taken as for [response between pods on different nodes](#pod-to-pod-on-another-node),
   except that in `nat44-in2out` on the **client's node** the source address `serverIP:serverPort`
   is translated back to service VIP `serviceIP:servicePort` (session is not -1
   in the packet trace)

Example SYN-ACK packet sent from server `10.1.2.4:8080`, acting as endpoint of service
`10.97.193.160:80`, back to client `10.1.1.3:49710`:
```
SYN-ACK from the server's node:
-------------------------------
02:24:27:765783: virtio-input
  virtio: hw_if_index 7 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:24:27:765786: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:1d:72:95:66
02:24:27:765789: ip4-input
  TCP: 10.1.2.4 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x23b4
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 49710
    seq. 0xfc736553 ack 0x27c7a68c
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x11a7
02:24:27:765791: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 7, next index 2, action: 2, match: acl 2 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0402010a00000000 0000000000000000 0301010a00000000 00070006c22e1f90 0712ffff00000007
   input sw_if_index 7 (lsb16 7) l3 ip4 10.1.2.4 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 49710 tcp flags (valid) 12 rsvd 0
02:24:27:765794: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 7, next index 3, session -1
02:24:27:765795: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 7, next index 0, session -1
02:24:27:765797: ip4-lookup
  fib 0 dpo-idx 25 flow hash: 0x00000000
  TCP: 10.1.2.4 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x23b4
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 49710
    seq. 0xfc736553 ack 0x27c7a68c
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x11a7
02:24:27:765798: ip4-load-balance
  fib 0 dpo-idx 25 flow hash: 0x00000000
  TCP: 10.1.2.4 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x23b4
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 49710
    seq. 0xfc736553 ack 0x27c7a68c
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x11a7
02:24:27:765800: ip4-rewrite
  tx_sw_if_index 3 dpo-idx 6 : ipv4 via 192.168.30.1 loop0: 1a2b3c4d5e011a2b3c4d5e020800 flow hash: 0x00000000
  00000000: 1a2b3c4d5e011a2b3c4d5e0208004500003c000040003f0624b40a0102040a01
  00000020: 01031f90c22efc73655327c7a68ca012712011a70000020405b40402
02:24:27:765800: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 3, next index 1, action: 3, match: acl -1 rule 6 trace_bits 80000000
  pkt info 0000000000000000 0402010a00000000 0000000000000000 0301010a00000000 00030006c22e1f90 0512ffff00000003
   output sw_if_index 3 (lsb16 3) l3 ip4 10.1.2.4 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 49710 tcp flags (valid) 12 rsvd 0
02:24:27:765802: loop0-output
  loop0
  IP4: 1a:2b:3c:4d:5e:02 -> 1a:2b:3c:4d:5e:01
  TCP: 10.1.2.4 -> 10.1.1.3
    tos 0x00, ttl 63, length 60, checksum 0x24b4
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 49710
    seq. 0xfc736553 ack 0x27c7a68c
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x11a7
02:24:27:765803: l2-input
  l2-input: sw_if_index 3 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02
02:24:27:765804: l2-input-classify
  l2-classify: sw_if_index 3, table 15, offset 0, next 18
02:24:27:765805: acl-plugin-in-ip4-l2
  acl-plugin: sw_if_index 3, next index 5, action: 2, match: acl 2 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0402010a00000000 0000000000000000 0301010a00000000 00030006c22e1f90 0712ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.2.4 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 49710 tcp flags (valid) 12 rsvd 0
02:24:27:765807: l2-fwd
  l2-fwd:   sw_if_index 3 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 bd_index 1
02:24:27:765809: l2-output
  l2-output: sw_if_index 4 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 data 08 00 45 00 00 3c 00 00 40 00 3f 06
02:24:27:765810: vxlan4-encap
  VXLAN encap to vxlan_tunnel0 vni 10
02:24:27:765811: ip4-load-balance
  fib 4 dpo-idx 24 flow hash: 0x00000002
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 254, length 110, checksum 0x1b2b
    fragment id 0x0000
  UDP: 25569 -> 4789
    length 90, checksum 0x0000
02:24:27:765811: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 5 : ipv4 via 192.168.16.1 GigabitEthernet0/8/0: 080027449fd8080027e057490800 flow hash: 0x00000002
  00000000: 080027449fd8080027e0574908004500006e00000000fd111c2bc0a81002c0a8
  00000020: 100163e112b5005a00000800000000000a001a2b3c4d5e011a2b3c4d
02:24:27:765812: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 1, next index 2, action: 1, match: acl 1 rule 8 trace_bits 00000000
  pkt info 0000000000000000 0210a8c000000000 0000000000000000 0110a8c000000000 0001001112b563e1 0400ffff00000001
   output sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.2 -> 192.168.16.1 l4 proto 17 l4_valid 1 port 25569 -> 4789 tcp flags (invalid) 00 rsvd 0
02:24:27:765813: nat44-in2out-output
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
02:24:27:765814: nat44-in2out-output-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session 2
02:24:27:765819: GigabitEthernet0/8/0-output
  GigabitEthernet0/8/0
  IP4: 08:00:27:e0:57:49 -> 08:00:27:44:9f:d8
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 25569 -> 4789
    length 90, checksum 0x0000
02:24:27:765822: GigabitEthernet0/8/0-tx
  GigabitEthernet0/8/0 tx queue 0
  buffer 0x15b1d: current data -50, length 124, free-list 0, clone-count 0, totlen-nifb 0, trace 0x1
                  nated l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 65535, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 78, phys_addr 0x1af6c7c0
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:e0:57:49 -> 08:00:27:44:9f:d8
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 25569 -> 4789
    length 90, checksum 0x0000


SYN-ACK from the client's node:
-------------------------------
02:26:06:587032: dpdk-input
  GigabitEthernet0/8/0 rx queue 0
  buffer 0x4a34: current data 14, length 110, free-list 0, clone-count 0, totlen-nifb 0, trace 0x19
                 l4-cksum-computed l4-cksum-correct l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 0, nb_segs 1, pkt_len 124
    buf_len 2176, data_len 124, ol_flags 0x0, data_off 128, phys_addr 0x70528d80
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:e0:57:49 -> 08:00:27:44:9f:d8
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 25569 -> 4789
    length 90, checksum 0x0000
02:26:06:587056: ip4-input
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 25569 -> 4789
    length 90, checksum 0x0000
02:26:06:587059: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 1, next index 2, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0210a8c000000000 0000000000000000 0110a8c000000000 0001001112b563e1 0600ffff00000001
   input sw_if_index 1 (lsb16 1) l3 ip4 192.168.16.2 -> 192.168.16.1 l4 proto 17 l4_valid 1 port 25569 -> 4789 tcp flags (invalid) 00 rsvd 0
02:26:06:587062: nat44-out2in
  NAT44_OUT2IN: sw_if_index 1, next index 1, session index 6
02:26:06:587064: ip4-lookup
  fib 0 dpo-idx 6 flow hash: 0x00000000
  UDP: 192.168.16.2 -> 192.168.16.1
    tos 0x00, ttl 253, length 110, checksum 0x1c2b
    fragment id 0x0000
  UDP: 25569 -> 4789
    length 90, checksum 0x0000
02:26:06:587066: ip4-local
    UDP: 192.168.16.2 -> 192.168.16.1
      tos 0x00, ttl 253, length 110, checksum 0x1c2b
      fragment id 0x0000
    UDP: 25569 -> 4789
      length 90, checksum 0x0000
02:26:06:587067: ip4-udp-lookup
  UDP: src-port 25569 dst-port 4789
02:26:06:587068: vxlan4-input
  VXLAN decap from vxlan_tunnel0 vni 10 next 1 error 0
02:26:06:587070: l2-input
  l2-input: sw_if_index 5 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02
02:26:06:587072: l2-fwd
  l2-fwd:   sw_if_index 5 dst 1a:2b:3c:4d:5e:01 src 1a:2b:3c:4d:5e:02 bd_index 1
02:26:06:587073: ip4-input
  TCP: 10.1.2.4 -> 10.1.1.3
    tos 0x00, ttl 63, length 60, checksum 0x24b4
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 49710
    seq. 0xfc736553 ack 0x27c7a68c
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x11a7
02:26:06:587073: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 3, next index 1, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0402010a00000000 0000000000000000 0301010a00000000 00030006c22e1f90 0712ffff00000003
   input sw_if_index 3 (lsb16 3) l3 ip4 10.1.2.4 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 49710 tcp flags (valid) 12 rsvd 0
02:26:06:587076: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 3, next index 3, session -1
02:26:06:587077: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 3, next index 0, session 4
02:26:06:587079: ip4-lookup
  fib 0 dpo-idx 8 flow hash: 0x00000000
  TCP: 10.97.193.160 -> 10.1.1.3
    tos 0x00, ttl 63, length 60, checksum 0x64b7
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 80 -> 49710
    seq. 0xfc736553 ack 0x27c7a68c
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x70ea
02:26:06:587080: ip4-rewrite
  tx_sw_if_index 6 dpo-idx 8 : ipv4 via 10.1.1.3 tap2: 00000000000202fe163f5f0f0800 flow hash: 0x00000000
  00000000: 00000000000202fe163f5f0f08004500003c000040003e0665b70a61c1a00a01
  00000020: 01030050c22efc73655327c7a68ca012712070ea0000020405b40402
02:26:06:587082: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 6, next index 1, action: 3, match: acl -1 rule 26 trace_bits 80000000
  pkt info 0000000000000000 a0c1610a00000000 0000000000000000 0301010a00000000 00060006c22e0050 0512ffff00000006
   output sw_if_index 6 (lsb16 6) l3 ip4 10.97.193.160 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 80 -> 49710 tcp flags (valid) 12 rsvd 0
02:26:06:587084: tap2-output
  tap2
  IP4: 02:fe:16:3f:5f:0f -> 00:00:00:00:00:02
  TCP: 10.97.193.160 -> 10.1.1.3
    tos 0x00, ttl 62, length 60, checksum 0x65b7
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 80 -> 49710
    seq. 0xfc736553 ack 0x27c7a68c
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x70ea
```

## Pod to Service with chosen backend in the host network stack

### Request
Request sent from a "client" pod with the source address `clientIP:clientPort`
destined to service `serviceIP:servicePort`, load-balanced to the endpoint
`serverIP:serverPort` on the host network stack of the same node:

 - the same steps are taken as for [request sent directly to a pod in the host](#pod-to-pod-in-the-host-network-stack),
   except that `nat44-out2in` translates destination address `serviceIP:servicePort`
   to randomly chosen endpoint `serverIP:serverPort` (session index is not -1 in the packet
   trace)
   

Example SYN packet sent from client `10.1.1.3:46310` to service `10.104.221.85:80`,
load-balanced to endpoint `10.20.0.2:8080` deployed in the host:
```
02:54:30:091783: virtio-input
  virtio: hw_if_index 6 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:54:30:091788: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:16:3f:5f:0f
02:54:30:091791: ip4-input
  TCP: 10.1.1.3 -> 10.104.221.85
    tos 0x00, ttl 64, length 60, checksum 0xe946
    fragment id 0x5eb4, flags DONT_FRAGMENT
  TCP: 46310 -> 80
    seq. 0xba5bf36d ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0xd22d
02:54:30:091794: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 6, next index 2, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 55dd680a00000000 000600060050b4e6 0702ffff00000006
   input sw_if_index 6 (lsb16 6) l3 ip4 10.1.1.3 -> 10.104.221.85 l4 proto 6 l4_valid 1 port 46310 -> 80 tcp flags (valid) 02 rsvd 0
02:54:30:091801: nat44-out2in
  NAT44_OUT2IN: sw_if_index 6, next index 1, session index 5
02:54:30:091884: ip4-lookup
  fib 0 dpo-idx 3 flow hash: 0x00000000
  TCP: 10.1.1.3 -> 10.20.0.2
    tos 0x00, ttl 64, length 60, checksum 0xc6ee
    fragment id 0x5eb4, flags DONT_FRAGMENT
  TCP: 46310 -> 8080
    seq. 0xba5bf36d ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x9095
02:54:30:091886: ip4-rewrite
  tx_sw_if_index 2 dpo-idx 3 : ipv4 via 172.30.1.2 tap0: 3e1b702d4d510123456789420800 flow hash: 0x00000000
  00000000: 3e1b702d4d5101234567894208004500003c5eb440003f06c7ee0a0101030a14
  00000020: 0002b4e61f90ba5bf36d00000000a002721090950000020405b40402
02:54:30:091888: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 2, next index 1, action: 1, match: acl 2 rule 3 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 0200140a00000000 000200061f90b4e6 0502ffff00000002
   output sw_if_index 2 (lsb16 2) l3 ip4 10.1.1.3 -> 10.20.0.2 l4 proto 6 l4_valid 1 port 46310 -> 8080 tcp flags (valid) 02 rsvd 0
02:54:30:091891: tap0-output
  tap0
  IP4: 01:23:45:67:89:42 -> 3e:1b:70:2d:4d:51
  TCP: 10.1.1.3 -> 10.20.0.2
    tos 0x00, ttl 63, length 60, checksum 0xc7ee
    fragment id 0x5eb4, flags DONT_FRAGMENT
  TCP: 46310 -> 8080
    seq. 0xba5bf36d ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x9095
```

### Response

For response sent from server `serverIP:serverPort` in the host stack, acting as endpoint
for service `serviceIP:servicePort`, back to the client `clientIP:clientPort`:

 - the same steps are taken as for [response sent directly from a pod in the host](#pod-to-pod-in-the-host-network-stack),
   except that in the 4th step `nat44-in2out` translates the source address `serverIP:serverPort`
   back to service VIP `serviceIP:servicePort` (session is not -1 in the packet trace)

Example SYN-ACK packet sent from server `10.20.0.2:8080` in the host stack,
acting as endpoint of service `10.104.221.85:80`, back to client `10.1.1.3:46310`:
```
02:54:30:091945: virtio-input
  virtio: hw_if_index 2 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:54:30:091947: ethernet-input
  IP4: 3e:1b:70:2d:4d:51 -> 01:23:45:67:89:42
02:54:30:091950: ip4-input
  TCP: 10.20.0.2 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x25a3
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 8080 -> 46310
    seq. 0x57f7b0c7 ack 0xba5bf36e
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0xdab4
02:54:30:091952: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 2, next index 1, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0200140a00000000 0000000000000000 0301010a00000000 00020006b4e61f90 0712ffff00000002
   input sw_if_index 2 (lsb16 2) l3 ip4 10.20.0.2 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 8080 -> 46310 tcp flags (valid) 12 rsvd 0
02:54:30:091957: nat44-in2out
  NAT44_IN2OUT_FAST_PATH: sw_if_index 2, next index 3, session -1
02:54:30:091959: nat44-in2out-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 2, next index 0, session 5
02:54:30:091961: ip4-lookup
  fib 0 dpo-idx 8 flow hash: 0x00000000
  TCP: 10.104.221.85 -> 10.1.1.3
    tos 0x00, ttl 64, length 60, checksum 0x47fb
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 80 -> 46310
    seq. 0x57f7b0c7 ack 0xba5bf36e
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x1c4d
02:54:30:091963: ip4-rewrite
  tx_sw_if_index 6 dpo-idx 8 : ipv4 via 10.1.1.3 tap2: 00000000000202fe163f5f0f0800 flow hash: 0x00000000
  00000000: 00000000000202fe163f5f0f08004500003c000040003f0648fb0a68dd550a01
  00000020: 01030050b4e657f7b0c7ba5bf36ea01271201c4d0000020405b40402
02:54:30:091964: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 6, next index 1, action: 3, match: acl -1 rule 32 trace_bits 80000000
  pkt info 0000000000000000 55dd680a00000000 0000000000000000 0301010a00000000 00060006b4e60050 0512ffff00000006
   output sw_if_index 6 (lsb16 6) l3 ip4 10.104.221.85 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 80 -> 46310 tcp flags (valid) 12 rsvd 0
02:54:30:091965: tap2-output
  tap2
  IP4: 02:fe:16:3f:5f:0f -> 00:00:00:00:00:02
  TCP: 10.104.221.85 -> 10.1.1.3
    tos 0x00, ttl 63, length 60, checksum 0x48fb
    fragment id 0x0000, flags DONT_FRAGMENT
  TCP: 80 -> 46310
    seq. 0x57f7b0c7 ack 0xba5bf36e
    flags 0x12 SYN ACK, tcp header: 40 bytes
    window 28960, checksum 0x1c4d
```

## Host to Service

### Request

For request sent from the host with the source address `hostIP:hostPort`
destined to service `serviceIP:servicePort`, load-balanced to the endpoint
`serverIP:serverPort` on the same node:

1. Connections initiated from the host stack of cluster nodes and destined
   to services are captured and proxied by iptable rules installed by Kube-proxy.
   The rules will randomly select one of the service endpoints and establish
   proxying for the connection.
   Request originally sent to `serviceIP:servicePort` will arrive to VPP via `tap0`
   already proxied to chosen `serverIP:serverPort`.
2. The redirected request is sent to the server via the same path as for [directly
   accessed pods from the host](#host-to-pod). In fact, from the VPP point of view
   the two scenarios are indistinguishable (i.e. equivalent packet trace).

### Response

For response sent from server `serverIP:serverPort`, acting as endpoint for service
`serviceIP:servicePort`, back to the client in the host stack `hostIP:hostPort`
on the same node:

1. Steps 1.-5. listed for the [response in the Host to Pod scenario](#host-to-pod)
   are taken to deliver the response into the host stack.
   In fact, from the VPP point of view the two scenarios are indistinguishable
   (i.e. equivalent packet trace).
2. In the host-stack, the transparent proxy configured by kube-proxy matches
   the dynamic entry created for the connection and translates the source address
   `serverIP:serverPort` back to service VIP `serviceIP:servicePort`    


[pod-to-pod-on-the-same-node-diagram]: pod-to-pod-on-the-same-node.png "Pod connecting to pod on the same node"
[pod-to-pod-on-another-node-diagram]: pod-to-pod-on-another-node.png "Pod connecting to pod on another node"
[policies-dev-guide]: POLICIES.md
[services-dev-guide]: SERVICES.md