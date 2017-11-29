#!/usr/bin/env python

import random
import socket
import struct

# Config
podLabel = "role: db"
numCidrs = 1000
numExcepts = 5
numPorts = 20

policyTemplate = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
  namespace: default
spec:
  policyTypes:
    - Ingress
    - Egress
  podSelector:
    matchLabels:
      {argPodLabel}
  ingress:
  - from:
{argIngressBlocks}{argIngressPorts}
  egress:
  - to:
{argEgressBlocks}{argEgressPorts}
"""

def maskIpAddr(ipAddr, maskLen):
    return ipAddr & (0xffffffff ^ ((1 << (32 - maskLen)) - 1))

def ipAddrToStr(ipAddr, maskLen):
    return socket.inet_ntoa(struct.pack('>I', ipAddr)) + "/" + str(maskLen)

def genIpBlocks():
    ipBlocks = ""
    for i in range(numCidrs):
        prefix = (i + 0x100) << 16
    	cidr = random.randint(prefix, prefix | 0xffff)
    	maskLen = random.randint(16, 24)
    	cidr = maskIpAddr(cidr, maskLen) 
    	ipBlock = "    - ipBlock:\n        cidr:%s\n        except:\n" % ipAddrToStr(cidr, maskLen)
    	for j in range(numExcepts):
    		exceptSubnet = random.randint(cidr, cidr | ((1 << (32 - maskLen)) - 1))
    		excMaskLen = random.randint(24, 32)
                exceptSubnet = maskIpAddr(exceptSubnet, excMaskLen)
                ipBlock += "        - %s\n" % ipAddrToStr(exceptSubnet, excMaskLen)
    	ipBlocks += ipBlock
    return ipBlocks

def genPorts():
    ports = "    ports:\n"
    for i in range(numPorts):
        protocol = random.randint(0, 1)
        protocolStr = "TCP"
        if protocol == 1:
            protocolStr = "UDP"
        port = random.randint(0, 65535)
        ports += "    - protocol: %s\n      port: %d\n" % (protocolStr, port)
    return ports

if __name__ == '__main__':
    ingressBlocks = genIpBlocks()
    ingressPorts = genPorts()
    egressBlocks = genIpBlocks()
    egressPorts = genPorts()
    
    print policyTemplate.format(argPodLabel=podLabel, argIngressBlocks=ingressBlocks,
            argEgressBlocks=egressBlocks, argIngressPorts=ingressPorts, argEgressPorts=egressPorts)
