*** Settings ***
Documentation    Test suite to test ldpreload functionality with iperf.
Resource         ${CURDIR}/../libraries/all_libs.robot
Suite Setup      OneNodeK8sSetup
Suite Teardown   OneNodeK8sTeardown

*** Variables ***
${CLIENT_FILE}   ${CURDIR}/../resources/one-ldpreload-client-iperf.yaml
${SERVER_FILE}   ${CURDIR}/../resources/one-ldpreload-server-iperf.yaml

*** Test Cases ***
Host_To_Pod_Iperf
    [Documentation]    Execute iperf3 comand from host towards server pod, checking return code is zero.
    [Setup]    Setup_Hosts_Connections
    [Timeout]    5 minutes
    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    iperf3 -V4d -c ${server_ip}    ignore_stderr=${True}
    [Teardown]    Teardown_Hosts_Connections

Pod_To_Pod_Iperf
    [Documentation]    Execute iperf3 comand from client pod towards server pod, checking return code is zero.
    [Setup]    Setup_Hosts_Connections
    [Timeout]    5 minutes
    KubeCtl.Execute_On_Pod    ${testbed_connection}    ${client_pod_name}    iperf3 -V4d -c ${server_ip}    ignore_stderr=${True}
    [Teardown]    Teardown_Hosts_Connections

Host_To_Pod_Iperf_Again
    [Documentation]    Execute iperf3 comand from host towards server pod, checking return code is zero.
    ...    This is to show whether the previous test case changes the result of this repeated test.
    [Setup]    Setup_Hosts_Connections
    [Timeout]    5 minutes
    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    iperf3 -V4d -c ${server_ip}    ignore_stderr=${True}
    [Teardown]    Teardown_Hosts_Connections

Pod_To_Pod_Iperf_Loop
    [Documentation]    Execute multiple iperf3 comands from client pod towards server pod sequentially,
    ...    checking return codes are zero.
    [Setup]    Setup_Hosts_Connections
    [Timeout]    5 minutes
    Repeat Keyword    15    KubeCtl.Execute_On_Pod    ${testbed_connection}    ${client_pod_name}    iperf3 -V4d -c ${server_ip}    ignore_stderr=${True}
    [Teardown]    Teardown_Hosts_Connections

*** Keywords ***
OneNodeK8sSetup
    [Documentation]    Execute common setup, reinit 1node cluster, deploy client and server pods.
    setup-teardown.Testsuite_Setup
    KubernetesEnv.Reinit_One_Node_Kube_Cluster
    ${client_pod_name} =    KubernetesEnv.Deploy_Pod_And_Verify_Running    ${testbed_connection}    ${CLIENT_FILE}    test-client-
    ${server_pod_name} =    KubernetesEnv.Deploy_Pod_And_Verify_Running    ${testbed_connection}    ${SERVER_FILE}    test-server-iperf-
    BuiltIn.Set_Suite_Variable    ${client_pod_name}
    BuiltIn.Set_Suite_Variable    ${server_pod_name}

OneNodeK8sTeardown
    [Documentation]    Log leftover output from pods, remove pods, execute common teardown.
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}    exp_nr_vswitch=1
    KubeCtl.Delete_F    ${testbed_connection}    ${CLIENT_FILE}
    KubeCtl.Delete_F    ${testbed_connection}    ${SERVER_FILE}
    Wait_Until_Pod_Removed    ${testbed_connection}    ${client_pod_name}
    Wait_Until_Pod_Removed    ${testbed_connection}    ${server_pod_name}
    setup-teardown.Testsuite Teardown

Setup_Hosts_Connections
    [Arguments]    ${user}=localadmin    ${password}=cisco123
    [Documentation]    Open and store two more SSH connections to master host, in them open
    ...    pod shells to client and server pod, parse their IP addresses and store them.
    Builtin.Log_Many    ${user}    ${password}
    ${conn} =     SSHLibrary.Get_Connection    ${testbed_connection}
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    ${server_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${server_connection}
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${client_connection}    ${client_pod_name}    prompt=#
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${server_connection}    ${server_pod_name}    prompt=#
    ${client_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${server_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${server_pod_name}
    ${server_ip} =     BuiltIn.Evaluate    &{server_pod_details}[${server_pod_name}]["IP"]
    ${client_ip} =     BuiltIn.Evaluate    &{client_pod_details}[${client_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${server_ip}
    BuiltIn.Set_Suite_Variable    ${client_ip}

Teardown_Hosts_Connections
    [Documentation]    Exit pod shells, close corresponding SSH connections.
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${client_connection}
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${server_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
    SSHLibrary.Switch_Connection    ${server_connection}
    SSHLibrary.Close_Connection
    KubeCtl.Logs    ${testbed_connection}    ${server_pod_name}
    KubeCtl.Logs    ${testbed_connection}    ${client_pod_name}
