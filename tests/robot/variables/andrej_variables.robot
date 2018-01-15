*** Settings ***
Resource                          common_variables.robot

*** Variables ***
${KUBE_CLUSTER_100_NODES}            1
${KUBE_CLUSTER_100_VM_1_PUBLIC_IP}   192.168.1.67
${KUBE_CLUSTER_100_VM_1_LOCAL_IP}    192.168.1.67
${KUBE_CLUSTER_100_VM_1_HOST_NAME}   frinx
${KUBE_CLUSTER_100_VM_1_USER}        frinx
${KUBE_CLUSTER_100_VM_1_PSWD}        frinx
${KUBE_CLUSTER_100_VM_1_ROLE}        master
${KUBE_CLUSTER_100_VM_1_LABEL}       client_node
#${KUBE_CLUSTER_1_VM_2_PUBLIC_IP}   192.168.1.67
#${KUBE_CLUSTER_1_VM_2_LOCAL_IP}    192.168.1.67
#${KUBE_CLUSTER_1_VM_2_HOST_NAME}   frinx
#${KUBE_CLUSTER_1_VM_2_USER}        frinx
#${KUBE_CLUSTER_1_VM_2_PSWD}        frinx
#${KUBE_CLUSTER_1_VM_2_ROLE}        slave
#${KUBE_CLUSTER_1_VM_2_LABEL}       server_node
${KUBE_CLUSTER_100_DOCKER_COMMAND}   docker

