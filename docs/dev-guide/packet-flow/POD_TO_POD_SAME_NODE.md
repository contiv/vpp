# Packet Flow between Pods on the same node

## Request

Request sent from a "client" pod with the source address `clientIP:clientPort`
destined to `serverIP:serverPort` of another "server" pod on the same node:

1. Inside the client pod, destination `serverIP` matches the default route
   configured for the pod by `remoteCNIserver.podDefaultRouteFromRequest()`.
    * default gateway IP address is the same for all pods on the same node -
      returned by `IPAM.PodGatewayIP()` as the first unicast IP address from
      the *subset* of `PodSubnetCIDR` allocated for the node. **Pod default GW
      IP is kept virtual** and never assigned to any pod or interface inside VPP.
      Do not confuse pod's TAP interface IP address on the VPP side with the
      default gateway. The IP address assigned on the VPP-side of the pod-VPP
      interconnection actually plays no role in the packet traversal, it serves
      merely as a marker for VPP to put the TAP  interface into the L3 mode.
2. Link-local route installed by `remoteCNIserver.podLinkRouteFromRequest()`
   informs the host stack that `PodGatewayIP` is on the same L2 network as the
   pod's `eth0` interface, even though the pod IP address is prefixed with `/32`.
3. Static ARP entry configured by `remoteCNIserver.podArpEntry()` maps
   `PodGatewayIP` to the MAC address of the VPP side of the pod's TAP interface,
   i.e. every pod translates `PodGatewayIP` to a different hardware address.
4. Packet arrives to VPP either through the `virtio-input`, if TAP version 2 is
   used, or through `tapcli-rx` for TAPv1.
5. If the client pod is referenced by ingress or egress policies, the (ingress)
   `Reflective ACL` will be traversed (node `acl-plugin-in-ip4-fa`), **allowing
   and reflecting the connection** (study [Policy dev guide][policy-dev-guide]
   to learn why).
6. `nat44-out2in` node checks if the destination address should be translated
   as an external IP into a local IP using any of the static mappings installed
   by the [service plugin][services-dev-guide] - in this case the destination
   is a real pod IP address, thus **no translation occurs** (`session index -1`
   in the packet trace).
7. Destination IP address matches static route installed for the server pod
   by `remoteCNIserver.vppRouteFromRequest()`. The server pod's TAP interface
   is selected for the output.
8. If the server pod is referenced by ingress or egress policies, the **combined
   ingress & egress policy rules installed as a single egress ACL** will be
   checked by the node `acl-plugin-out-ip4-fa`.
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

## Response

Response sent from the pod with the server application `serverIP:serverPort`
back to the client `clientIP:clientPort` on the same node:

1. Default route + Link-local route + static ARP entry are used to sent
   the response to VPP via pod's `eth0` TAP interface (see the request flow,
   steps 1.-4., to learn the details)  
2. If the server pod is referenced by ingress or egress policies, the (ingress)
   `Reflective ACL` will be traversed (node `acl-plugin-in-ip4-fa`), **allowing
   and reflecting the connection**. The reflection has no effect in this case,
   since the connection was already allowed in the direction of the request.
3. `nat44-in2out` node checks if the source address should be translated as
   a local IP into an external IP using any of the static mappings installed
   by the [service plugin][services-dev-guide] - in this case the server is being
   accessed directly, not via service VIP, thus **no translation occurs**
   (`session -1` in the packet trace).
4. Destination IP address matches static route installed for the client pod
   by `remoteCNIserver.vppRouteFromRequest()`. The client pod's TAP interface
   is selected for the output.
5. If the client pod is referenced by ingress or egress policies, the combined
   ingress & egress policy rules installed as a single egress ACL will be
   checked by the node `acl-plugin-out-ip4-fa`.
   The desired behaviour is, however, to always allow connection if it has got
   this far - the **policies should be only checked in the direction of the
   request**. The `Reflective ACL` has already created a free pass for all
   responses in the connection, thus the client's egress ACL is ignored.
6. Static ARP entry configured by `remoteCNIserver.vppArpEntry()` maps `clientIP`
   to the hardware address of the client pod's `eth0` interface. It is required
   by the STN plugin that all pods use the same MAC address `00:00:00:00:00:02`.
7. Request arrives to the client pod's host stack.

Example SYN-ACK packet sent from server `10.1.1.9:8080` back to client
`10.1.1.12:39820`:
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

## Diagram

![Pod connecting to pod on the same node][pod-to-pod-on-the-same-node-diagram]


[pod-to-pod-on-the-same-node-diagram]: pod-to-pod-same-node.png
[policies-dev-guide]: ../POLICIES.md
[services-dev-guide]: ../SERVICES.md