#!/usr/bin/env bash

kubectl exec -n kube-system $1 cat /var/run/secrets/kubernetes.io/serviceaccount/token > /var/run/secrets/kubernetes.io/serviceaccount/token
kubectl exec -n kube-system $1 cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt > /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
kubectl exec -n kube-system $1 cat /var/run/secrets/kubernetes.io/serviceaccount/namespace > /var/run/secrets/kubernetes.io/serviceaccount/namespace
