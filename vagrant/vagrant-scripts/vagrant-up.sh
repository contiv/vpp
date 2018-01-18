#!/bin/bash

set -euo pipefail

export K8S_NODE_OS=${K8S_NODE_OS:-ubuntu}
export K8S_NODES=${K8S_NODES:-1}
export VAGRANT_DEFAULT_PROVIDER=${VAGRANT_DEFAULT_PROVIDER:-virtualbox}

vagrant up 
