#!/usr/bin/env bash

# A utility to cleanup Kubernetes & Contiv installation on a node.

set -euo pipefail

usage() {
    echo Usage: "$0"
    echo
    echo You must run this utility with superuser provileges.
    echo
}

while getopts "h" opt
do
    case "$opt" in
    h)
        usage
        exit 0
        ;;
    esac
done

echo Cleaning up Kubernetes...
kubeadm reset
echo Cleaning up Contiv-VPP crumbs...
rm -rf /var/etcd/contiv-data
rm -rf /var/bolt/bolt.db
docker rmi -f $(docker images -a)
echo Done.