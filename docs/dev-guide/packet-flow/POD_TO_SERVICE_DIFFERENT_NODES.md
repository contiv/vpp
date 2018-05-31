# Packet flow for Pod to Service chosen endpoint from a different node

## Request

For request sent from a "client" pod with the source address `clientIP:clientPort`
destined to service `serviceIP:servicePort`, load-balanced to the endpoint
`serverIP:serverPort` from another node:

 - the same steps are taken as for [request between pods on different nodes][pod-to-pod-on-different-node],
   except that `nat44-out2in` between client's TAP and `loop0` (the first pass through this node)
   translates destination address `serviceIP:servicePort` to a randomly chosen
   endpoint `serverIP:serverPort` from another node (session index is not -1
   in the packet trace)

Example SYN packet sent from client `10.1.1.3:49710` to service `10.97.193.160:80`,
load-balanced to endpoint `10.1.2.4:8080` from another node (trace taken from
both nodes):
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

## Response

For response sent from server `serverIP:serverPort`, acting as endpoint for
service `serviceIP:servicePort`, back to the client `clientIP:clientPort`
deployed on another node:

 - the same steps are taken as for [response between pods on different nodes][pod-to-pod-on-different-node],
   except that in `nat44-in2out` on the **client's node** the source address
   `serverIP:serverPort` is translated back to service VIP `serviceIP:servicePort`
   (session is not -1 in the packet trace)

Example SYN-ACK packet sent from server `10.1.2.4:8080`, acting as one of
the endpoints for service `10.97.193.160:80`, back to client `10.1.1.3:49710`:
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

## Diagram

The packets traverse the **same sequence of nodes** as for the [communication
between pods on different nodes][pod-to-pod-on-different-node]:

![Pod connecting to service endpoint on a different node][pod-to-pod-different-nodes-diagram]


[pod-to-pod-different-nodes-diagram]: pod-to-pod-different-nodes.png
[pod-to-pod-on-different-node]: POD_TO_POD_DIFFERENT_NODES.md 