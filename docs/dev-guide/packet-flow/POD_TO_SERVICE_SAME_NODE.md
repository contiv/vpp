# Packet flow for Pod to Service with chosen endpoint from the same node

## Request

For request sent from a "client" pod with the source address `clientIP:clientPort`
destined to service `serviceIP:servicePort`, load-balanced to the endpoint
`serverIP:serverPort` on the same node:

 - the same steps are taken as for [request between pods on the same node][pod-to-pod-on-the-same-node],
   except that in the 6th step `nat44-out2in` translates destination address
   `serviceIP:servicePort` to a randomly chosen endpoint `serverIP:serverPort`
   (session index is not -1 in the packet trace)

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

## Response

For response sent from server `serverIP:serverPort`, acting as endpoint for
service `serviceIP:servicePort`, back to the client `clientIP:clientPort`:

 - the same steps are taken as for [response between pods on the same node][pod-to-pod-on-the-same-node],
   except that in the 3th step `nat44-in2out` translates the source address
   `serverIP:serverPort` back to service VIP `serviceIP:servicePort`
   (session is not -1 in the packet trace)

Example SYN-ACK packet sent from server `10.1.1.5:8080`, acting as one of
the endpoints for service `10.104.221.85:80`, back to client `10.1.1.3:51082`:
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

## Diagram

The packets traverse the **same sequence of nodes** as for the [communication
between pods on the same node][pod-to-pod-on-the-same-node]:
![Pod connecting to service endpoint on the same node][pod-to-pod-on-the-same-node-diagram]


[pod-to-pod-on-the-same-node-diagram]: pod-to-pod-same-node.png
[pod-to-pod-on-the-same-node]: POD_TO_POD_SAME_NODE.md