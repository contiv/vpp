#!/bin/bash

#kubectl apply -f ./ldpreload_server_vpp.yaml
kubectl apply -f ./ldpreload_server_iperf.yaml
kubectl apply -f ./ldpreload_client.yaml

sleep 30
kubectl get pods

#VPP_SERVER_NAME=$(kubectl get pod -l "app=test-server-vpp" -o jsonpath='{.items[0].metadata.name}')
#VPP_SERVER_IP=$(kubectl get pod -l "app=test-server-vpp" -o jsonpath='{.items[0].status.podIP}')
IPERF_SERVER_NAME=$(kubectl get pod -l "app=test-server-iperf" -o jsonpath='{.items[0].metadata.name}')
IPERF_SERVER_IP=$(kubectl get pod -l "app=test-server-iperf" -o jsonpath='{.items[0].status.podIP}')
CLIENT_NAME=$(kubectl get pod -l "app=test-client" -o jsonpath='{.items[0].metadata.name}')

echo $IPERF_SERVER_NAME
echo $IPERF_SERVER_IP
echo $CLIENT_NAME

#kubectl exec $CLIENT_NAME -- /vpp/sock_test_client -B -X $VPP_SERVER_IP 22000
kubectl exec $CLIENT_NAME -- iperf3 -V4d -c $IPERF_SERVER_IP
