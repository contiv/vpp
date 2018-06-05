# Packet Flow between Pods on different nodes

## Request

Request sent from a "client" pod with the source address `clientIP:clientPort`
destined to `serverIP:serverPort` of another "server" pod from a different node:

1. Request arrives from client to VPP through the same path as for the
   [request between pods on the same node][pod-to-pod-on-the-same-node],
   traversing through the `Reflective ACL` and no-op `nat44-out2in` (steps 1.-6.).
2. Destination IP address `serverIP` matches static route installed by
   `remoteCNIserver.routeToOtherHostPods()`, forwarding the packet via
   the opposite side of the VXLAN tunnel between this and the destination node.
   All VXLAN interfaces are inside a single bridge domain (ID=1), which the packet
   is scheduled to enter through BVI `loop0`.
3. Before the packet gets sent into the bridge-domain with VXLANs, (egress)
   `Global ACL` is applied inside the VPP node `acl-plugin-out-ip4-fa`,
   confronting the connection parameters with the **egress policies of the client's
   pod** (if there are any). The connection is allowed if client's egress policies
   permit connections destined to `serverIP:serverPort`. 
4. The packet enters BD `ID=1` via BVI `loop0`.
5. Ingress `Reflective ACL` for `loop0` allows and reflects the connection.
6. Static ARP entry, installed by `remoteCNIserver.vxlanArpEntry()` for every
   other node, tells VPP which VXLAN tunnel the packet should travel through
   to meet the IP address selected by the route in the step 2. at the other end.
7. Static L2 FIB entry installed by `remoteCNIserver.vxlanFibEntry()` maps the IP
   address of the VXLAN tunnel's opposite side with the corresponding MAC address.
   This prevents from ARP flooding between nodes.
8. The packet is encapsulated by the VXLAN interface (node `vxlan4-encap`).
   The original packet is carried inside a UDP packet on port 4789 with this
   node's IP as the source and the target node as the destination.
9. The encapsulated packet is routed out via GbE interface.
10. The egress `Global ACL` also assigned to GbE is visited on more time
    (node `acl-plugin-out-ip4-fa`) - the **encapsulated traffic is always
    permitted**.
11. `nat44-in2out-output`, i.e. NAT in the post-routing phase, applies the
    identity mapping installed for VXLAN to **prevent from source-NATing
    of the inter-cluster traffic**.
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
18. [Steps 7.-10. listed for the request between pods on the same node][pod-to-pod-on-the-same-node]
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

## Response

Response sent from the pod with the server application `serverIP:serverPort`
back to the client `clientIP:clientPort` on a different node:

1. Response arrives to VPP through the same path as for the [response between
   pods on the same node][pod-to-pod-on-the-same-node],
   traversing through the `Reflective ACL` and no-op `nat44-in2out` (steps 1.-3.).
2. Destination IP address `clientIP` matches static route installed by
   `remoteCNIserver.routeToOtherHostPods()`, forwarding the packet via
   the opposite side of the VXLAN tunnel between this and the destination node.
   All VXLAN interfaces are inside a single bridge domain (ID=1), which the
   packet is scheduled to enter through BVI `loop0`.
3. Before the packet gets sent into the bridge-domain with VXLANs, (egress)
   `Global ACL` is applied inside the VPP node `acl-plugin-out-ip4-fa`.
   The `Reflective ACL` also assigned to `loop0` has already created a free pass
   for all responses in the connection (step 16. for the request), thus the
   `Global ACL` is ignored.
4. The packet enters BD `ID=1` via BVI `loop0`.
5. Ingress `Reflective ACL` for `loop0` has no effect in this case -
   the connection was already allowed in the direction of the request.   
6. Steps 6.-12. of the request are also followed here to deliver the packet
   VXLAN-encapsulated to the opposite node.
7. On the client's node, ingress `Reflective ACL` for GbeE has no effect -
   the connection was already allowed in the direction of the request.
8. `nat44-out2in` NAT node applies identity mapping for VXLAN port - i.e. NAT is
   effectively bypassed while the traffic is still encapsulated.
9. When leaving the bridge domain, `Reflective ACL` assigned on the ingress
   side of `loop0` is once again applied with no effect.  
10. `nat44-in2out` sees the packet requires no source-NAT to be applied, i.e.
    the packet is not a response from a service.
11. [steps 4.-7. listed for the response between pods on the same node][pod-to-pod-on-the-same-node]
    are also followed here to deliver the packet into to client's pod.  

Example SYN-ACK packet sent from server `10.1.2.13:8080` back to the client
`10.1.1.12:60996`:
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

## Diagram

![Pod connecting to pod on a different node][pod-to-pod-different-nodes-diagram]


[pod-to-pod-different-nodes-diagram]: pod-to-pod-different-nodes.png 
[pod-to-pod-on-the-same-node]: POD_TO_POD_SAME_NODE.md
[policies-dev-guide]: ../POLICIES.md
[services-dev-guide]: ../SERVICES.md