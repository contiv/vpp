# Packet flow for connection from the host stack to Pod

## Request

Request sent from the host with the source address `hostIP:hostPort` destined
to a "server" pod `serverIP:serverPort` (attached to VPP) on the same node:

1. Static route installed by `remoteCNIserver.routePODsFromHost()` on every
   node's host stack sends traffic destined to any address from `PodSubnetCIDR`
   (including `serverIP`) via `vpp1` - host's side of the TAP interface
   connecting VPP with the host (`tap0` is the VPP side).
2. Host stack determines physical address of `tap0` dynamically, i.e. no static
   ARP is configured by the agent.
3. `Reflective ACL` assigned to `tap0` **allows and reflects the connection**.
4. `nat44-in2out` node checks if the source address should be translated
   a as local IP into an external IP using any of the static mappings installed
   by the [service plugin][services-dev-guide] - but this is not a response
   from a service VIP, thus **no translation occurs** (`session -1` in the packet
   trace).
5. [steps 7.-10. listed for the request between pods on the same node][pod-to-pod-on-the-same-node]
   are also followed here to deliver the packet into to server's pod.
   The only exception here is that there are no egress policy rules to apply -
   Contiv/VPP does not support policies assigned to pods in the host network
   stack.
   
Example SYN packet sent from the host `172.30.1.2:32966` to server
`10.1.1.6:8080`:
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

## Response

Response sent from the pod with the server application `serverIP:serverPort`
back to the host `hostIP:hostPort` on the same node:

1. Response arrives to VPP from the server pod through the same path as for
   the [response between pods on the same node][pod-to-pod-on-the-same-node],
   traversing through the `Reflective ACL` and no-op `nat44-in2out` (steps 1.-3.).
2. `remoteCNIserver.routesToHost()` configures one static route to VPP for every
   interface in the host stack (including `hostIP`) to go via `tap0`, connecting
   VPP with the host.
3. Before the response gets sent back into the host via `tap0`, (egress)
   `Global ACL` is applied inside the VPP node `acl-plugin-out-ip4-fa`.
   The connection was already permitted and reflected by the `Reflective ACL`
   assigned to `tap0`, hence the `Global ACL` is bypassed.
4. `tap0` is the only interface in VPP with no static ARPs configured.
   The hardware address of the TAP's host side (`vpp1`) is discovered dynamically
   using a broadcast ARP request.  
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

## Diagram

![Accessing Pod from to the host stack][host-to-pod-diagram]


[host-to-pod-diagram]: host-to-pod.png
[pod-to-pod-on-the-same-node]: POD_TO_POD_SAME_NODE.md
[policies-dev-guide]: ../POLICIES.md
[services-dev-guide]: ../SERVICES.md