# Packet flow in Contiv/VPP

This guide provides a detailed description of paths traversed by request and
response packets inside Contiv/VPP Kubernetes cluster under different situations.

## Index

1. [Pod to Pod on the same node][pod-to-pod-on-the-same-node]
2. [Pod to Pod on a different node][pod-to-pod-on-different-node]
3. [Pod to Host][pod-to-host]
4. [Host to Pod][host-to-pod]
5. [Pod to Internet][pod-to-internet]
6. [Pod to Service with chosen endpoint from the same node][pod-to-service-same-node]
7. [Pod to Service with chosen endpoint from a different node][pod-to-service-different-node]
8. [Pod to Service with chosen endpoint in the host network stack][pod-to-service-in-host]
9. [Host to Service][host-to-service]


[pod-to-pod-on-the-same-node]: packet-flow/POD_TO_POD_SAME_NODE.md
[pod-to-pod-on-different-node]: packet-flow/POD_TO_POD_DIFFERENT_NODES.md
[pod-to-host]: packet-flow/POD_TO_HOST.md
[host-to-pod]: packet-flow/HOST_TO_POD.md
[pod-to-internet]: packet-flow/POD_TO_INTERNET.md
[pod-to-service-same-node]: packet-flow/POD_TO_SERVICE_SAME_NODE.md
[pod-to-service-different-node]: packet-flow/POD_TO_SERVICE_DIFFERENT_NODES.md
[pod-to-service-in-host]: packet-flow/POD_TO_SERVICE_HOST.md
[host-to-service]: packet-flow/HOST_TO_SERVICE.md

[policies-dev-guide]: POLICIES.md
[services-dev-guide]: SERVICES.md