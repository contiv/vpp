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
    Execute On Machine       ${machine}                df
    Execute On Machine       ${machine}                free
    Execute On Machine       ${machine}                ifconfig -a
    Execute On Machine       ${machine}                ps aux
    Execute On Machine       ${machine}                echo $PATH

Create Connections To Kube Cluster
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    Open SSH Connection    vm_${index}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_PUBLIC_IP}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_USER}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_PSWD}

Make Datastore Snapshots
    [Arguments]            ${tag}=notag
    Log                    ${tag}
    ${prefix}=             Create Next Snapshot Prefix
    Take ETCD Snapshots    ${prefix}_${tag}

Get ETCD Dump
    ${command}=         Set Variable    ${DOCKER_COMMAND} exec etcd etcdctl get --prefix="true" ""
    ${out}=             Execute On Machine    docker    ${command}    log=false
    [Return]            ${out}

Take ETCD Snapshots
    [Arguments]         ${tag}
    Log                 ${tag}
    ${dump}=            Get ETCD Dump
    Append To File      ${RESULTS_FOLDER}/etcd_dump-${tag}.txt    ${dump}
    ${errors}=          Get Lines Containing String    ${dump}    /error/
    ${status}=          Run Keyword And Return Status    Should Be Empty    ${errors}
    Run Keyword If      ${status}==False         Log     Errors detected in keys: ${errors}    level=WARN
    
Create Next Snapshot Prefix
    ${prefix}=          Evaluate    str(${snapshot_num}).zfill(2)
    ${snapshot_num}=    Evaluate    ${snapshot_num}+1
    Set Global Variable  ${snapshot_num}
    [Return]            ${prefix}

Check Agent Logs For Errors
    @{logs}=    OperatingSystem.List Files In Directory    ${RESULTS_FOLDER}/    *_container_agent.log
    Log List    ${logs}
    :FOR    ${log}    IN    @{logs}
    \    ${data}=    OperatingSystem.Get File    ${RESULTS_FOLDER}/${log}
    \    Should Not Contain    ${data}    exited: agent (exit status
    \    Should Not Contain    ${data}    exited: vpp (exit status
