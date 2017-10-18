[Documentation]     Keywords for testsuite setup and teardown

*** Settings ***
Resource      ${ENV}_setup-teardown.robot

*** Variables ***
${snapshot_num}       0

*** Keywords ***
Testsuite Setup
    [Documentation]    *Testsuite Setup*
    Discard Old Results
    Create Connections To Kube Cluster
#    Make Datastore Snapshots    startup

Testsuite Teardown
    [Documentation]    *Testsuite Teardown*
#    Make Datastore Snapshots    teardown
    Log All SSH Outputs
    Get Connections
    Close All Connections

Discard Old Results
    Remove Directory    ${RESULTS_FOLDER}    recursive=True
    Create Directory    ${RESULTS_FOLDER}

Log All SSH Outputs
    [Documentation]           *Log All SSH Outputs*
    ...                       Logs all connections outputs
    [Timeout]                 120s
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    Log vm_${index} Output

Log ${machine} Output
    [Documentation]         *Log ${machine} Output*
    ...                     Logs actual ${machine} output from begining
    Log                     ${machine}
    Switch Connection       ${machine}
    ${out}=                 Read    delay=${SSH_READ_DELAY}s
    Log                     ${out}
    Append To File          ${RESULTS_FOLDER}/output_${machine}.log    ${out}

Get Machine Status
    [Arguments]              ${machine}
    [Documentation]          *Get Machine Status ${machine}*
    ...                      Executing df, free, ifconfig -a, ps -aux... on ${machine}
    Log                      ${machine}
    Execute On Machine       ${machine}                whoami
    Execute On Machine       ${machine}                pwd       
    Execute On Machine       ${machine}                df
    Execute On Machine       ${machine}                free
    Execute On Machine       ${machine}                ifconfig -a
    Execute On Machine       ${machine}                ps aux
    Execute On Machine       ${machine}                export
    Execute On Machine       ${machine}                docker images
    Execute On Machine       ${machine}                docker ps -as
    Run Keyword If           "${machine}"=="vm_1"      Execute On Machine    ${machine}    kubectl get nodes
    Run Keyword If           "${machine}"=="vm_1"      Execute On Machine    ${machine}    kubectl get pods

Create Connections To Kube Cluster
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    Open SSH Connection    vm_${index}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_PUBLIC_IP}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_USER}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_PSWD}
    \    Get Machine Status    vm_${index}

Make Datastore Snapshots
    [Arguments]            ${tag}=notag
    Log                    ${tag}
    ${prefix}=             Create Next Snapshot Prefix
#    Take ETCD Snapshots    ${prefix}_${tag}

Create Next Snapshot Prefix
    ${prefix}=          Evaluate    str(${snapshot_num}).zfill(2)
    ${snapshot_num}=    Evaluate    ${snapshot_num}+1
    Set Global Variable  ${snapshot_num}
    [Return]            ${prefix}

