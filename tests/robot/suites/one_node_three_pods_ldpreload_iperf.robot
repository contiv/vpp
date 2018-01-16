*** Settings ***
Documentation    Test suite to test ldpreload functionality with 2 iperf server pods.
Resource         ${CURDIR}/../libraries/all_libs.robot
Suite Setup      OneNodeK8sSetup
Suite Teardown   OneNodeK8sTeardown

*** Variables ***
${CLIENT_FILE}    ${CURDIR}/../resources/one-ldpreload-client-iperf.yaml
${SERVER1_FILE}   ${CURDIR}/../resources/one-ldpreload-server-iperf.yaml
${SERVER2_FILE}   ${CURDIR}/../resources/one-ldpreload-server2-iperf.yaml

*** Test Cases ***
Client_To_Server1
    [Setup]    Setup_Hosts_Connections
    [Timeout]   2 minutes
    ${stdout} =    KubeCtl.Execute_On_Pod    ${testbed_connection}    ${client_pod_name}    iperf3 -V4d -c ${server1_ip}    ignore_stderr=${True}
    Log    ${stdout}
    [Teardown]    Teardown_Hosts_Connections

Client_To_Server2
    [Setup]    Setup_Hosts_Connections
    [Timeout]   2 minutes
    ${stdout} =    KubeCtl.Execute_On_Pod    ${testbed_connection}    ${client_pod_name}    iperf3 -V4d -c ${server2_ip}    ignore_stderr=${True}
    Log    ${stdout}
    [Teardown]    Teardown_Hosts_Connections

Host_To_Server1
    [Setup]    Setup_Hosts_Connections
    [Timeout]    2 minutes
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    iperf3 -V4d -c ${server1_ip}    ignore_stderr=${True}
    Log    ${stdout}
    [Teardown]    Teardown_Hosts_Connections

Host_To_Server2
    [Setup]    Setup_Hosts_Connections
    [Timeout]    2 minutes
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    iperf3 -V4d -c ${server2_ip}    ignore_stderr=${True}
    Log    ${stdout}
    [Teardown]    Teardown_Hosts_Connections

*** Keywords ***
OneNodeK8sSetup
    [Documentation]    Execute common setup, reinit 1node cluster, deploy client and server pods.
    setup-teardown.Testsuite_Setup
    KubernetesEnv.Reinit_One_Node_Kube_Cluster
    ${client_pod_name} =    KubernetesEnv.Deploy_Pod_And_Verify_Running    ${testbed_connection}    ${CLIENT_FILE}    test-client-
    ${server1_pod_name} =    KubernetesEnv.Deploy_Pod_And_Verify_Running    ${testbed_connection}    ${SERVER1_FILE}    test-server-iperf-
    ${server2_pod_name} =    KubernetesEnv.Deploy_Pod_And_Verify_Running    ${testbed_connection}    ${SERVER2_FILE}    test-server2-iperf-
    BuiltIn.Set_Suite_Variable    ${client_pod_name}
    BuiltIn.Set_Suite_Variable    ${server1_pod_name}
    BuiltIn.Set_Suite_Variable    ${server2_pod_name}

OneNodeK8sTeardown
    [Documentation]    Log leftover output from pods, remove pods, execute common teardown.
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}    exp_nr_vswitch=1
    KubeCtl.Delete_F    ${testbed_connection}    ${CLIENT_FILE}
    KubeCtl.Delete_F    ${testbed_connection}    ${SERVER1_FILE}
    KubeCtl.Delete_F    ${testbed_connection}    ${SERVER2_FILE}
    Wait_Until_Pod_Removed    ${testbed_connection}    ${client_pod_name}
    Wait_Until_Pod_Removed    ${testbed_connection}    ${server1_pod_name}
    Wait_Until_Pod_Removed    ${testbed_connection}    ${server2_pod_name}
    setup-teardown.Testsuite Teardown

Setup_Hosts_Connections
    [Arguments]    ${user}=${KUBE_CLUSTER_${CLUSTER_ID}_VM_1_USER}    ${password}=${KUBE_CLUSTER_${CLUSTER_ID}_VM_1_PSWD}
    [Documentation]    Open and store two more SSH connections to master host, in them open
    ...    pod shells to client and server pod, parse their IP addresses and store them.
    Builtin.Log_Many    ${user}    ${password}
    ${conn} =     SSHLibrary.Get_Connection    ${testbed_connection}
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    ${server1_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${server1_connection}
    ${server2_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${server2_connection}
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${client_connection}    ${client_pod_name}    prompt=#
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${server1_connection}    ${server1_pod_name}    prompt=#
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${server2_connection}    ${server2_pod_name}    prompt=#
    ${client_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${server1_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${server1_pod_name}
    ${server2_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${server2_pod_name}
    ${client_ip} =     BuiltIn.Evaluate    &{client_pod_details}[${client_pod_name}]["IP"]
    ${server1_ip} =     BuiltIn.Evaluate    &{server1_pod_details}[${server1_pod_name}]["IP"]
    ${server2_ip} =     BuiltIn.Evaluate    &{server2_pod_details}[${server2_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${client_ip}
    BuiltIn.Set_Suite_Variable    ${server1_ip}
    BuiltIn.Set_Suite_Variable    ${server2_ip}

Teardown_Hosts_Connections
    [Documentation]    Exit pod shells, close corresponding SSH connections.
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${client_connection}
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${server1_connection}
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${server2_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
    SSHLibrary.Switch_Connection    ${server1_connection}
    SSHLibrary.Close_Connection
    SSHLibrary.Switch_Connection    ${server2_connection}
    SSHLibrary.Close_Connection
