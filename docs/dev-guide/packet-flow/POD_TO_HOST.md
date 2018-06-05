# Packet flow for connection from Pod to the host stack

## Request

Request sent from a "client" pod with the source address `clientIP:clientPort`
destined to "server" `serverIP:serverPort` inside the host network stack
of the same node:

1. Request arrives from client to VPP through the same path as for
   the [request between pods on the same node][pod-to-pod-on-the-same-node],
   traversing through the `Reflective ACL` and no-op `nat44-out2in` (steps 1.-6.).
2. Since the server is inside the host network stack, the IP address it has
   assigned is one from the host interfaces. `remoteCNIserver.routesToHost()`
   installs one static route to VPP for every interface in the host stack
   to go via `tap0`,  connecting VPP with the host.
3. Before the packet gets sent into the host via `tap0`, (egress) `Global ACL`
   is applied inside the VPP node `acl-plugin-out-ip4-fa`, confronting the
   connection parameters with the **egress policies of the client's pod**
   (if there are any). The connection is allowed if client's egress policies
   permit connections destined to `serverIP:serverPort`.
   Note: ingress policies assigned to the server are ignored - Contiv/VPP
         does not support policies for pods inside the host network stack. 
4. `tap0` is the only interface in VPP with no static ARPs configured.
   The hardware address of the TAP's host side (`vpp1`) is discovered dynamically
   using a broadcast ARP request.  
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

## Response

Response sent from the server application `serverIP:serverPort` running
in the host network stack, back to the client `clientIP:clientPort` inside its
own network namespace (i.e. attached to VPP) on the same node:

1. Static route installed by `remoteCNIserver.routePODsFromHost()` on every
   node's host stack sends traffic destined to any address from `PodSubnetCIDR`
   (including `clientIP`) via `vpp1` - host's side of the TAP interface connecting
   VPP with the host (`tap0` is the VPP side).
2. Host stack determines physical address of `tap0` dynamically, i.e. no static
   ARP configured by the agent.
3. `Reflective ACL` assigned to `tap0` is taken with no effect - connection was
   already allowed in the direction of the request.
4. `nat44-in2out` node checks if the source address should be translated
   as a local IP into an external IP using any of the static mappings installed
   by the [service plugin][services-dev-guide] - in this case the server is being
   accessed directly, not via service VIP, thus **no translation occurs**
   (`session -1` in the packet trace).
5. [steps 4.-7. listed for the response between pods on the same node][pod-to-pod-on-the-same-node]
   are also followed here to deliver the packet into to client's pod. 
    
Example SYN-ACK packet sent from server `10.20.0.2:8080` back to client
`10.1.1.3:54252`:
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

## Diagram
![Pod connecting to the host stack][pod-to-host-diagram]


[pod-to-host-diagram]: pod-to-host.png
[pod-to-pod-on-the-same-node]: POD_TO_POD_SAME_NODE.md
[policies-dev-guide]: ../POLICIES.md
[services-dev-guide]: ../SERVICES.md