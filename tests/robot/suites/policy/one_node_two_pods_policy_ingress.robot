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
Check_Allow_TCP_Port_4444_On_Server_From_Client
    [Setup]    Setup_Hosts_Connections
    KubeCtl.Apply_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_tcp_4444_server_from_client.yaml
    Get_Traffic_Status    tcp_port=4444    udp_port=7000
    Get_Traffic_Status    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_tcp_4444_server_from_client.yaml
    [Teardown]    Teardown_Hosts_Connections

Check_Allow_UDP_Port_7000_On_Server_From_Client
    [Setup]    Setup_Hosts_Connections
    KubeCtl.Apply_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_udp_7000_server_from_client.yaml
    Get_Traffic_Status    tcp_port=4444    udp_port=7000
    Get_Traffic_Status    tcp_port=4444    udp_port=5000
    KubeCtl.Delete_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_udp_7000_server_from_client.yaml
    [Teardown]    Teardown_Hosts_Connections

Check_Allow_Port_5000_On_Server_From_Client
    [Setup]    Setup_Hosts_Connections
    KubeCtl.Apply_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_port_5000_server_from_client.yaml
    Get_Traffic_Status    tcp_port=4444    udp_port=5000
    Get_Traffic_Status    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_port_5000_server_from_client.yaml
    [Teardown]    Teardown_Hosts_Connections

Check_Allow_TCP_Port_4444_On_Server_From_Nginx
    [Setup]    Setup_Hosts_Connections
    KubeCtl.Apply_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_tcp_4444_server_from_nginx.yaml
    Get_Traffic_Status    tcp_port=4444    udp_port=7000
    Get_Traffic_Status    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_tcp_4444_server_from_nginx.yaml
    [Teardown]    Teardown_Hosts_Connections

Check_Allow_UDP_Port_7000_On_Server_From_Nginx
    [Setup]    Setup_Hosts_Connections
    KubeCtl.Apply_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_udp_7000_server_from_nginx.yaml
    Get_Traffic_Status    tcp_port=4444    udp_port=7000
    Get_Traffic_Status    tcp_port=4444    udp_port=5000
    KubeCtl.Delete_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_udp_7000_server_from_nginx.yaml
    [Teardown]    Teardown_Hosts_Connections

Check_Allow_Port_5000_On_Server_From_Nginx
    [Setup]    Setup_Hosts_Connections
    KubeCtl.Apply_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_port_5000_server_from_nginx.yaml
    Get_Traffic_Status    tcp_port=4444    udp_port=5000
    Get_Traffic_Status    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${TEST_DATA_FOLDER}/allow_port_5000_server_from_nginx.yaml
    [Teardown]    Teardown_Hosts_Connections




*** Keywords ***

Get_Traffic_Status
    [Arguments]    ${tcp_port}=4444    ${udp_port}=7000
    Log Many    ${tcp_port}    ${udp_port}
    ${report}=    Set Variable    ${EMPTY}
    ${ping_client_server}    ${ping_server_client}=    Pod_To_Pod_Ping
    BuiltIn.Set_Suite_Variable    ${ping_client_server}
    BuiltIn.Set_Suite_Variable    ${ping_server_client}
    ${report}=    Set Variable If    "5 received, 0% packet loss" in """${ping_client_server}"""    ${report}PING client -> server OK${\n}    ${report}PING client -> server ERROR${\n}
    ${report}=    Set Variable If    "5 received, 0% packet loss" in """${ping_server_client}"""    ${report}PING server -> client OK${\n}    ${report}PING server -> client ERROR${\n}

    ${udp_client_server}    ${udp_server_client}=    Pod_To_Pod_Udp    ${udp_port}
    BuiltIn.Set_Suite_Variable    ${udp_client_server}
    BuiltIn.Set_Suite_Variable    ${udp_server_client}
    ${report}=    Set Variable If    "Text to be received" in """${udp_client_server}"""    ${report}UDP client -> server OK${\n}    ${report}UDP client -> server ERROR${\n}
    ${report}=    Set Variable If    "Text to be received" in """${udp_server_client}"""    ${report}UDP server -> client OK${\n}    ${report}UDP server -> client ERROR${\n}

    ${tcp_client_server}    ${tcp_server_client}=    Pod_To_Pod_Tcp    ${tcp_port}
    BuiltIn.Set_Suite_Variable    ${tcp_client_server}
    BuiltIn.Set_Suite_Variable    ${tcp_server_client}
    ${report}=    Set Variable If    "Text to be received" in """${tcp_client_server}"""    ${report}TCP client -> server OK${\n}    ${report}TCP client -> server ERROR${\n}
    ${report}=    Set Variable If    "Text to be received" in """${tcp_server_client}"""    ${report}TCP server -> client OK${\n}    ${report}TCP server -> client ERROR${\n}

    ${ping_host_server}    ${ping_host_client}=    Host_To_Pod_Ping
    BuiltIn.Set_Suite_Variable    ${ping_host_server}
    BuiltIn.Set_Suite_Variable    ${ping_host_client}
    ${report}=    Set Variable If    "5 received, 0% packet loss" in """${ping_host_server}"""    ${report}PING host -> server OK${\n}    ${report}PING host -> server ERROR${\n}
    ${report}=    Set Variable If    "5 received, 0% packet loss" in """${ping_host_client}"""    ${report}PING host -> client OK${\n}    ${report}PING host -> client ERROR${\n}

    ${udp_host_server}    ${udp_host_client}=    Host_To_Pod_Udp    ${udp_port}
    BuiltIn.Set_Suite_Variable    ${udp_host_server}
    BuiltIn.Set_Suite_Variable    ${udp_host_client}
    ${report}=    Set Variable If    "Text to be received" in """${udp_host_server}"""    ${report}UDP host -> server OK${\n}    ${report}UDP host -> server ERROR${\n}
    ${report}=    Set Variable If    "Text to be received" in """${udp_host_client}"""    ${report}UDP host -> client OK${\n}    ${report}UDP host -> client ERROR${\n}

    ${tcp_host_server}    ${tcp_host_client}=    Host_To_Pod_Tcp    ${tcp_port}
    BuiltIn.Set_Suite_Variable    ${tcp_host_server}
    BuiltIn.Set_Suite_Variable    ${tcp_host_client}
    ${report}=    Set Variable If    "Text to be received" in """${tcp_host_server}"""    ${report}TCP host -> server OK${\n}    ${report}TCP host -> server ERROR${\n}
    ${report}=    Set Variable If    "Text to be received" in """${tcp_host_client}"""    ${report}TCP host -> client OK${\n}    ${report}TCP host -> client ERROR${\n}

    Log    ${report}

Pod_To_Pod_Ping
    [Documentation]    Execute "ping -c 5" command between pods (both ways), require no packet loss.
    ${ping_client_server} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${server_ip}    ssh_session=${client_connection}
#    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${ping_server_client} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${client_ip}    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
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
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${client_ip} ${udp_port}    ssh_session=${server_connection}
    SSHLibrary.Write    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
    ${udp_server_client} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    [Return]    ${udp_client_server}    ${udp_server_client}

Pod_To_Pod_Tcp
    [Documentation]    Start TCP server, start client sending the message, stop server, check message has been received, stop client.
    [Arguments]    ${tcp_port}=4444
    ${text} =    BuiltIn.Set_Variable    Text to be received
    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${client_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p ${tcp_port}    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${server_ip} ${tcp_port} < some.file    ssh_session=${client_connection}
    ${tcp_client_server} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p ${tcp_port}    ssh_session=${client_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${client_ip} ${tcp_port} < some.file    ssh_session=${server_connection}
    ${tcp_server_client} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
    [Return]    ${tcp_client_server}    ${tcp_server_client}

Host_To_Pod_Ping
    [Documentation]    Execute "ping -c 5" command from host to both pods, require no packet loss.
    ${ping_host_server} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    ping -c 5 ${server_ip}
#    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${ping_host_client} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    ping -c 5 ${client_ip}
#    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Return]    ${ping_host_server}    ${ping_host_client}

Host_To_Pod_Udp
    [Documentation]    The same as Pod_To_Pod_Udp but client is on host instead of pod.
    [Arguments]    ${udp_port}=7000
    ${text} =    BuiltIn.Set_Variable    Text to be received
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -ul -p ${udp_port}    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${server_ip} ${udp_port}    ssh_session=${testbed_connection}
    SSHLibrary.Write    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$
    ${udp_host_server} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -ul -p ${udp_port}    ssh_session=${client_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${client_ip} ${udp_port}    ssh_session=${testbed_connection}
    SSHLibrary.Write    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$
    ${udp_host_client} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
    [Return]    ${udp_host_server}    ${udp_host_client}

Host_To_Pod_Tcp
    [Documentation]    The same as Pod_To_Pod_Tcp but client is on host instead of pod.
    [Arguments]    ${tcp_port}=4444
    ${text} =    BuiltIn.Set_Variable    Text to be received
    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${testbed_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p ${tcp_port}    ssh_session=${server_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${server_ip} ${tcp_port} < some.file    ssh_session=${testbed_connection}
    ${tcp_host_server} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$
    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${testbed_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p ${tcp_port}    ssh_session=${client_connection}
    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${client_ip} ${tcp_port} < some.file    ssh_session=${testbed_connection}
    ${tcp_host_client} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$
    [Return]    ${tcp_host_server}    ${tcp_host_client}

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
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    client    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    ${server_connection} =    SSHLibrary.Open_Connection    ${conn.host}    server    timeout=10
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
