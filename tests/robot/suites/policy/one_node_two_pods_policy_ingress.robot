*** Settings ***
Documentation     Test suite to test basic ping, udp, tcp and dns functionality of the network plugin.
Resource          ${CURDIR}/../../libraries/KubernetesEnv.robot
Resource          ${CURDIR}/../../variables/${VARIABLES}_variables.robot
Resource          ${CURDIR}/../../libraries/setup-teardown.robot
Suite Setup       OneNodeK8sSetup
Suite Teardown    OneNodeK8sTeardown

*** Variables ***
${VARIABLES}      common
${ENV}            common

*** Test Cases ***
Check_Allow_TCP_Port
    [Setup]    Setup_Hosts_Connections
    KubeCtl.Apply_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_tcp_4444_server_from_client.yaml
    Get_Traffic_Status    tcp_port=4444    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_tcp_4444_server_from_client.yaml
    [Teardown]    Teardown_Hosts_Connections



*** Keywords ***

Get_Traffic_Status
    [Arguments]    ${tcp_port}=4444    ${udp_port}=7000
    ${ping_client_server}    ${ping_server_client}=    Pod_To_Pod_Ping
    BuiltIt.Set_Suite_Variable    ${ping_client_server}
    BuiltIt.Set_Suite_Variable    ${ping_server_client}
    ${udp_client_server}    ${udp_server_client}=    Pod_To_Pod_Udp    ${udp_port}
    BuiltIt.Set_Suite_Variable    ${udp_client_server}
    BuiltIt.Set_Suite_Variable    ${udp_server_client}


Pod_To_Pod_Ping
    [Documentation]    Execute "ping -c 5" command between pods (both ways), require no packet loss.
#    [Setup]    Setup_Hosts_Connections
    ${ping_client_server} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${server_ip}    ssh_session=${client_connection}
#    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${ping_server_client} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${client_ip}    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
#    [Teardown]    Teardown_Hosts_Connections
    [Return]    ${ping_client_server}    ${ping_server_client}

Pod_To_Pod_Udp
    [Documentation]    Start UDP server and client, send message, stop both and check the message has been reseived.
    [Arguments]    ${udp_port}=7000
    ${text} =    BuiltIn.Set_Variable    Text to be received
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -ul -p ${udp_port}    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${server_ip} ${udp_port}    ssh_session=${client_connection}
    SSHLibrary.Write    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
    ${udp_client_server} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -ul -p ${udp_port}    ssh_session=${client_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${server_ip} ${udp_port}    ssh_session=${server_connection}
    SSHLibrary.Write    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
    ${udp_server_client} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    [Return]    ${udp_client_server}    ${udp_server_client}







Pod_To_Pod_Tcp
    [Documentation]    Start TCP server, start client sending the message, stop server, check message has been received, stop client.
    ${text} =    BuiltIn.Set_Variable    Text to be received
    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${client_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p 4444    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${server_ip} 4444 < some.file    ssh_session=${client_connection}
    ${server_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${client_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}

Host_To_Pod_Ping
    [Documentation]    Execute "ping -c 5" command from host to both pods, require no packet loss.
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    ping -c 5 ${server_ip}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    ping -c 5 ${client_ip}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss

Host_To_Pod_Udp
    [Documentation]    The same as Pod_To_Pod_Udp but client is on host instead of pod.
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -ul -p 7000    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${server_ip} 7000    ssh_session=${testbed_connection}
    ${text} =    BuiltIn.Set_Variable    Text to be received
    SSHLibrary.Write    ${text}
    ${client_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$
    ${server_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${server_stdout}    ${text}

Host_To_Pod_Tcp
    [Documentation]    The same as Pod_To_Pod_Tcp but client is on host instead of pod.
    ${text} =    BuiltIn.Set_Variable    Text to be received
    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${testbed_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p 4444    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${server_ip} 4444 < some.file    ssh_session=${testbed_connection}
    ${server_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${client_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$

OneNodeK8sSetup
    [Documentation]    Execute common setup, reinit 1node cluster, deploy client and server pods.
    setup-teardown.Testsuite_Setup
    KubernetesEnv.Reinit_One_Node_Kube_Cluster
    KubernetesEnv.Deploy_Client_And_Server_Pod_And_Verify_Running    ${testbed_connection}

OneNodeK8sTeardown
    [Documentation]    Log leftover output from pods, remove pods, execute common teardown.
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}    exp_nr_vswitch=1
    KubernetesEnv.Remove_Client_And_Server_Pod_And_Verify_Removed    ${testbed_connection}
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
