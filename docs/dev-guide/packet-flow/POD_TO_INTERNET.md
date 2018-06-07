# Packet flow for Pod accessing Internet

## Request

Request sent from a "client" pod with the source address `clientIP:clientPort`
destined to "server" `serverIP:serverPort` from the Internet (or generally
outside of the cluster):

1. Request arrives from client to VPP through the same path as for
   the [request between pods on the same node][pod-to-pod-on-the-same-node],
   traversing through the `Reflective ACL` and no-op `nat44-out2in` (steps 1.-6.).
2. Default route sends packet through the GbE interface.
3. The egress `Global ACL` assigned to GbE is applied inside the VPP node
   `acl-plugin-out-ip4-fa`. The connection is allowed if client's egress policies
   permit connections destined to `serverIP:serverPort`.
4. `nat44-in2out-output`, i.e. NAT in the post-routing phase, **dynamically
   translates the source address `clientIP` to `nodeIP`**. 
5. The packet leaves the node via the GbE interface.

Example SYN packet sent from client `10.1.1.3:41084` to server `31.134.97.51:80`
from outside of the cluster (`192.168.16.1` is node IP):
```
02:06:32:879780: virtio-input
  virtio: hw_if_index 6 next-index 4 vring 0 len 74
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
02:06:32:879786: ethernet-input
  IP4: 00:00:00:00:00:02 -> 02:fe:16:3f:5f:0f
02:06:32:879789: ip4-input
  TCP: 10.1.1.3 -> 31.134.97.51
    tos 0x00, ttl 64, length 60, checksum 0x3154
    fragment id 0x7dab, flags DONT_FRAGMENT
  TCP: 41084 -> 80
    seq. 0x940482c0 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x91d0
02:06:32:879791: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 6, next index 2, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 3361861f00000000 000600060050a07c 0702ffff00000006
   input sw_if_index 6 (lsb16 6) l3 ip4 10.1.1.3 -> 31.134.97.51 l4 proto 6 l4_valid 1 port 41084 -> 80 tcp flags (valid) 02 rsvd 0
02:06:32:879798: nat44-out2in
  NAT44_OUT2IN: sw_if_index 6, next index 1, session index -1
02:06:32:879813: ip4-lookup
  fib 0 dpo-idx 1 flow hash: 0x00000000
  TCP: 10.1.1.3 -> 31.134.97.51
    tos 0x00, ttl 64, length 60, checksum 0x3154
    fragment id 0x7dab, flags DONT_FRAGMENT
  TCP: 41084 -> 80
    seq. 0x940482c0 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x91d0
02:06:32:879815: ip4-rewrite
  tx_sw_if_index 1 dpo-idx 1 : ipv4 via 192.168.16.100 GigabitEthernet0/8/0: 08002702a536080027449fd80800 flow hash: 0x00000000
  00000000: 08002702a536080027449fd808004500003c7dab40003f0632540a0101031f86
  00000020: 6133a07c0050940482c000000000a002721091d00000020405b40402
02:06:32:879816: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 1, next index 2, action: 1, match: acl 2 rule 14 trace_bits 00000000
  pkt info 0000000000000000 0301010a00000000 0000000000000000 3361861f00000000 000100060050a07c 0502ffff00000001
   output sw_if_index 1 (lsb16 1) l3 ip4 10.1.1.3 -> 31.134.97.51 l4 proto 6 l4_valid 1 port 41084 -> 80 tcp flags (valid) 02 rsvd 0
02:06:32:879818: nat44-in2out-output
  NAT44_IN2OUT_FAST_PATH: sw_if_index 6, next index 3, session -1
02:06:32:879819: nat44-in2out-output-slowpath
  NAT44_IN2OUT_SLOW_PATH: sw_if_index 6, next index 0, session 6
02:06:32:879825: GigabitEthernet0/8/0-output
  GigabitEthernet0/8/0
  IP4: 08:00:27:44:9f:d8 -> 08:00:27:02:a5:36
  TCP: 192.168.16.1 -> 31.134.97.51
    tos 0x00, ttl 63, length 60, checksum 0x6cae
    fragment id 0x7dab, flags DONT_FRAGMENT
  TCP: 25801 -> 80
    seq. 0x940482c0 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x07de
02:06:32:879826: GigabitEthernet0/8/0-tx
  GigabitEthernet0/8/0 tx queue 0
  buffer 0x172e1: current data 0, length 74, free-list 0, clone-count 0, totlen-nifb 0, trace 0x14
                  nated l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 65535, nb_segs 1, pkt_len 74
    buf_len 2176, data_len 74, ol_flags 0x0, data_off 128, phys_addr 0x6e9cb8c0
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:44:9f:d8 -> 08:00:27:02:a5:36
  TCP: 192.168.16.1 -> 31.134.97.51
    tos 0x00, ttl 63, length 60, checksum 0x6cae
    fragment id 0x7dab, flags DONT_FRAGMENT
  TCP: 25801 -> 80
    seq. 0x940482c0 ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 29200, checksum 0x07de
```

## Response

Response sent from the cluster-outside server application `serverIP:serverPort`
back to the client `clientIP:clientPort`:

1. Response arrives to VPP via `dpdk-input` node.    
2. Ingress `Reflective ACL` for GbeE is applied with no effect.
3. `nat44-out2in` **translates the destination address `nodeIP` back to
   `clientIP`**.
4. [steps 4.-7. listed for the response between pods on the same node][pod-to-pod-on-the-same-node]
   are also followed here to deliver the packet into to client's pod. 

Example SYN-ACK packet sent from server `31.134.97.51:80` back to client
`10.1.1.3:41084` (`192.168.16.1` is node IP):
```
02:06:32:880926: dpdk-input
  GigabitEthernet0/8/0 rx queue 0
  buffer 0x2f8b: current data 14, length 46, free-list 0, clone-count 0, totlen-nifb 0, trace 0x15
                 l4-cksum-computed l4-cksum-correct l2-hdr-offset 0 l3-hdr-offset 14 
  PKT MBUF: port 0, nb_segs 1, pkt_len 60
    buf_len 2176, data_len 60, ol_flags 0x0, data_off 128, phys_addr 0x704be340
    packet_type 0x0 l2_len 0 l3_len 0 outer_l2_len 0 outer_l3_len 0
  IP4: 08:00:27:02:a5:36 -> 08:00:27:44:9f:d8
  TCP: 31.134.97.51 -> 192.168.16.1
    tos 0x00, ttl 63, length 44, checksum 0x239a
    fragment id 0x06d0
  TCP: 80 -> 25801
    seq. 0xc9a75001 ack 0x940482c1
    flags 0x12 SYN ACK, tcp header: 24 bytes
    window 65535, checksum 0xb12b
02:06:32:880948: ip4-input
  TCP: 31.134.97.51 -> 192.168.16.1
    tos 0x00, ttl 63, length 44, checksum 0x239a
    fragment id 0x06d0
  TCP: 80 -> 25801
    seq. 0xc9a75001 ack 0x940482c1
    flags 0x12 SYN ACK, tcp header: 24 bytes
    window 65535, checksum 0xb12b
02:06:32:880951: acl-plugin-in-ip4-fa
  acl-plugin: sw_if_index 1, next index 2, action: 2, match: acl 3 rule 0 trace_bits 00000000
  pkt info 0000000000000000 3361861f00000000 0000000000000000 0110a8c000000000 0001000664c90050 0712ffff00000001
   input sw_if_index 1 (lsb16 1) l3 ip4 31.134.97.51 -> 192.168.16.1 l4 proto 6 l4_valid 1 port 80 -> 25801 tcp flags (valid) 12 rsvd 0
02:06:32:880957: nat44-out2in
  NAT44_OUT2IN: sw_if_index 1, next index 1, session index 6
02:06:32:880959: ip4-lookup
  fib 0 dpo-idx 8 flow hash: 0x00000000
  TCP: 31.134.97.51 -> 10.1.1.3
    tos 0x00, ttl 63, length 44, checksum 0xe93f
    fragment id 0x06d0
  TCP: 80 -> 41084
    seq. 0xc9a75001 ack 0x940482c1
    flags 0x12 SYN ACK, tcp header: 24 bytes
    window 65535, checksum 0x3b1e
02:06:32:880961: ip4-rewrite
  tx_sw_if_index 6 dpo-idx 8 : ipv4 via 10.1.1.3 tap2: 00000000000202fe163f5f0f0800 flow hash: 0x00000000
  00000000: 00000000000202fe163f5f0f08004500002c06d000003e06ea3f1f8661330a01
  00000020: 01030050a07cc9a75001940482c16012ffff3b1e0000020405b40000
02:06:32:880963: acl-plugin-out-ip4-fa
  acl-plugin: sw_if_index 6, next index 1, action: 3, match: acl -1 rule 130 trace_bits 80000000
  pkt info 0000000000000000 3361861f00000000 0000000000000000 0301010a00000000 00060006a07c0050 0512ffff00000006
   output sw_if_index 6 (lsb16 6) l3 ip4 31.134.97.51 -> 10.1.1.3 l4 proto 6 l4_valid 1 port 80 -> 41084 tcp flags (valid) 12 rsvd 0
02:06:32:880965: tap2-output
  tap2
  IP4: 02:fe:16:3f:5f:0f -> 00:00:00:00:00:02
  TCP: 31.134.97.51 -> 10.1.1.3
    tos 0x00, ttl 62, length 44, checksum 0xea3f
    fragment id 0x06d0
  TCP: 80 -> 41084
    seq. 0xc9a75001 ack 0x940482c1
    flags 0x12 SYN ACK, tcp header: 24 bytes
    window 65535, checksum 0x3b1e
```

## Diagram
![Pod accessing Internet][pod-to-internet-diagram]


[pod-to-internet-diagram]: pod-to-internet.png
[pod-to-pod-on-the-same-node]: POD_TO_POD_SAME_NODE.md
[policies-dev-guide]: ../POLICIES.md
[services-dev-guide]: ../SERVICES.md