# SFC Tests

Basic suite of service chain tests.

Requirements:
 - k8s-cluster with at least worker 3 nodes

Usage:
 - use kubectl to apply either Linux or VPP service chain and cnfs:
   $ kubectl apply -f cnfs-linux.yaml && kubectl apply -f sfc-linux.yaml
 - run the test script:
   $ ./sfc-linux.sh
   $ echo $?
 - cleanup service chain and pods:
   $ kubectl delete -f cnfs-linux.yaml && kubectl delete -f sfc-linux.yaml
