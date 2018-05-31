# Packet flow for connection from the host stack to Service

## Request

For request sent from the host with the source address `hostIP:hostPort`
destined to service `serviceIP:servicePort`, load-balanced to the endpoint
`serverIP:serverPort` running inside pod on the same node:

1. Connections initiated from the host stack of cluster nodes and destined
   to services are captured and proxied by iptable rules installed by Kube-proxy.
   The rules will randomly select one of the service endpoints and establish
   proxying for the connection.
   Request originally sent to `serviceIP:servicePort` will arrive to VPP via `tap0`
   already proxied to a chosen `serverIP:serverPort`.
2. The redirected request is sent to the server via the same path as for [directly
   accessed pods from the host][host-to-pod]. In fact, from the VPP point of view
   the two scenarios are indistinguishable (i.e. equivalent packet traces).

## Response

For response sent from server `serverIP:serverPort`, acting as an endpoint for
service `serviceIP:servicePort`, back to the client in the host stack
`hostIP:hostPort` on the same node:

1. Steps 1.-5. listed for the [response in the Host to Pod scenario][host-to-pod]
   are taken to deliver the response into the host stack.
   In fact, from the VPP point of view the two scenarios are indistinguishable
   (i.e. equivalent packet traces).
2. In the host-stack, the transparent proxy configured by kube-proxy matches
   a dynamic entry created for the connection and translates the source address
   `serverIP:serverPort` back to service VIP `serviceIP:servicePort`    

## Diagram

![Accessing Service from the host stack][host-to-service-diagram]


[host-to-service-diagram]: host-to-service.png
[host-to-pod]: HOST_TO_POD.md
