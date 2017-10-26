#!/bin/bash
rm -rf $HOME/.kube
sudo kubeadm reset
sudo -E kubeadm init --token-ttl 0 --pod-network-cidr=192.168.0.0/16
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl apply -f http://docs.projectcalico.org/v2.4/getting-started/kubernetes/installation/hosted/kubeadm/1.6/calico.yaml
kubectl get pods --all-namespaces
kubectl taint nodes --all node-role.kubernetes.io/master-
