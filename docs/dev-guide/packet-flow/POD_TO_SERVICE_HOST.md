# Packet flow for Pod to Service with chosen endpoint in the host network stack

## Request
Request sent from a "client" pod with the source address `clientIP:clientPort`
destined to service `serviceIP:servicePort`, load-balanced to an endpoint
`serverIP:serverPort` on the host network stack of the same node:

 - the same steps are taken as for the [request sent directly to the host][pod-to-host],
   except that `nat44-out2in` translates destination address `serviceIP:servicePort`
   to a randomly chosen endpoint `serverIP:serverPort` (session index is not -1
   in the packet trace)
   

Example SYN packet sent from client `10.1.1.3:46310` to service `10.104.221.85:80`,
load-balanced to endpoint `10.20.0.2:8080` deployed in the host network stack:
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

## Response

For response sent from server `serverIP:serverPort` in the host stack, acting as
one of the endpoints for service `serviceIP:servicePort`, back to the client
`clientIP:clientPort`:

 - the same steps are taken as for the [response sent directly from the host][pod-to-host],
   except that in the 4th step `nat44-in2out` translates the source address
   `serverIP:serverPort` back to service VIP `serviceIP:servicePort` (session
   is not -1 in the packet trace)

Example SYN-ACK packet sent from server `10.20.0.2:8080` in the host stack,
acting as one of the endpoints for service `10.104.221.85:80`, back to client
`10.1.1.3:46310`:
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

## Diagram 

The packets traverse the **same sequence of nodes** regardless of whether the
host stack is accessed via service IP or [directly][pod-to-host]:
![Pod connecting to service endpoint in the host stack][pod-to-host-diagram]


[pod-to-host-diagram]: pod-to-host.png
[pod-to-host]: POD_TO_HOST.md