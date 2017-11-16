*** Settings ***
Documentation     Keywords for testsuite setup and teardown.
...               TODO: Describe \${snapshot_num} (or remove it).
Library           OperatingSystem
Library           SSHLibrary
Resource          ${CURDIR}/SshCommons.robot
Resource          ${CURDIR}/${ENV}_setup-teardown.robot

*** Variables ***
${snapshot_num}       0
${VM_SSH_ALIAS_PREFIX}     vm_

*** Keywords ***
Testsuite_Setup
    [Documentation]    Perform actions common for setup of every suite.
    Discard_Old_Results
    Create_Connections_To_Kube_Cluster

Testsuite_Teardown
    [Documentation]    Perform actions common for teardown of every suite.
    Log_All_SSH_Outputs
    SSHLibrary.Get_Connections
    SSHLibrary.Close_All_Connections

Discard_Old_Results
    [Documentation]    Remove and re-create ${RESULTS_FOLDER}.
    OperatingSystem.Remove_Directory    ${RESULTS_FOLDER}    recursive=True
    OperatingSystem.Create_Directory    ${RESULTS_FOLDER}

Log_All_Ssh_Outputs
    [Documentation]    Call Log_\${machine}_Output for every cluster node.
    [Timeout]    120s
    : FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    Log_${VM_SSH_ALIAS_PREFIX}${index}_Output

Log_${machine}_Output
    [Documentation]    Switch to \${machine} SSH connection, read with delay of ${SSH_READ_DELAY}, Log and append to log file.
    BuiltIn.Log_Many    ${machine}
    BuiltIn.Comment    TODO: Rewrite this keyword with ${machine} being explicit argument.
    SSHLibrary.Switch_Connection    ${machine}
    ${out} =    SSHLibrary.Read    delay=${SSH_READ_DELAY}s
    BuiltIn.Log    ${out}
    OperatingSystem.Append_To_File    ${RESULTS_FOLDER}/output_${machine}.log    ${out}

Get_Machine_Status
    [Arguments]    ${machine}
    [Documentation]    Execute df, free, ifconfig -a, ps -aux... on \${machine}, assuming ssh connection there is active.
    BuiltIn.Log_Many    ${machine}
    SshCommons.Execute_Command_And_Log    whoami
    SshCommons.Execute_Command_And_Log    pwd
    SshCommons.Execute_Command_And_Log    df
    SshCommons.Execute_Command_And_Log    free
    SshCommons.Execute_Command_And_Log    ifconfig -a
    SshCommons.Execute_Command_And_Log    ps aux
    SshCommons.Execute_Command_And_Log    export
    SshCommons.Execute_Command_And_Log    docker images
    SshCommons.Execute_Command_And_Log    docker ps -as
    BuiltIn.Return_From_Keyword_If    """${machine}""" != """${VM_SSH_ALIAS_PREFIX}1"""
    SshCommons.Execute_Command_And_Log    kubectl get nodes
    SshCommons.Execute_Command_And_Log    kubectl get pods    ignore_stderr=True

Create_Connections_To_Kube_Cluster
    [Documentation]    Create connection and log machine status for each node. Leave active connection pointing to the first node (master).
    : FOR    ${index}    IN RANGE    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}    0    -1
    \    SshCommons.Open_Ssh_Connection    ${VM_SSH_ALIAS_PREFIX}${index}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_PUBLIC_IP}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_USER}    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_PSWD}
    \    Get_Machine_Status    ${VM_SSH_ALIAS_PREFIX}${index}

Make_Datastore_Snapshots
    [Arguments]    ${tag}=notag
    [Documentation]    Log ${tag}, compute next prefix (and do nothing with it).
    BuiltIn.Log_Many    ${tag}
    ${prefix} =    Create_Next_Snapshot_Prefix

Create_Next_Snapshot_Prefix
    [Documentation]    Contruct new prefix, store next snapshot num. Return the prefix.
    ${prefix} =    BuiltIn.Evaluate    str(${snapshot_num}).zfill(2)
    ${snapshot_num} =    BuiltIn.Evaluate    ${snapshot_num}+1
    BuiltIn.Set_Global_Variable    ${snapshot_num}
    [Return]    ${prefix}
