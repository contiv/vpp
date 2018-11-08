#!/usr/bin/env bash

# This script performs the cleanup of k8s installation that uses the
# Contiv CNI plugin. It must be executed as root.

set -euo pipefail

echo Resetting kubelet installation
kubeadm reset

echo Deleting contiv data
rm -rf /var/etcd/contiv-data

echo Deleting bolt data
rm -rf /var/bolt/bolt.db

echo Done.
