*** Settings ***
Documentation     Test suite to test basic ping, udp, tcp and dns functionality of the network plugin.
Resource          ${CURDIR}/../../libraries/all_libs.robot
Suite Setup       OneNodeK8sSetup
Suite Teardown    OneNodeK8sTeardown
Test Setup        Test_Case_Setup
Test Teardown     Test_Case_Teardown

*** Test Cases ***
Check_Allow_TCP_Port_4444_On_Server_From_Client
    ${policy_name}=    BuiltIn.Set_Variable    allow_tcp_4444_server_from_client
    KubeCtl.Apply_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    Get_VPP_Status
    ${status1}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=7000
    ${status2}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    BuiltIn.Should_Be_True    ${status1} and ${status2}

Check_Allow_UDP_Port_7000_On_Server_From_Client
    ${policy_name}=    BuiltIn.Set_Variable    allow_udp_7000_server_from_client
    KubeCtl.Apply_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    Get_VPP_Status
    ${status1}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=7000
    ${status2}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=5000
    KubeCtl.Delete_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    BuiltIn.Should_Be_True    ${status1} and ${status2}

Check_Allow_Port_5000_On_Server_From_Client
    ${policy_name}=    BuiltIn.Set_Variable    allow_port_5000_server_from_client
    KubeCtl.Apply_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    Get_VPP_Status
    ${status1}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=5000
    ${status2}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    BuiltIn.Should_Be_True    ${status1} and ${status2}

Check_Allow_TCP_Port_4444_On_Server_From_Nginx
    ${policy_name}=    BuiltIn.Set_Variable    allow_tcp_4444_server_from_nginx
    KubeCtl.Apply_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    Get_VPP_Status
    ${status1}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=7000
    ${status2}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    BuiltIn.Should_Be_True    ${status1} and ${status2}

Check_Allow_UDP_Port_7000_On_Server_From_Nginx
    ${policy_name}=    BuiltIn.Set_Variable    allow_udp_7000_server_from_nginx
    KubeCtl.Apply_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    Get_VPP_Status
    ${status1}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=7000
    ${status2}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=5000
    KubeCtl.Delete_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    BuiltIn.Should_Be_True    ${status1} and ${status2}

Check_Allow_Port_5000_On_Server_From_Nginx
    ${policy_name}=    BuiltIn.Set_Variable    allow_port_5000_server_from_nginx
    KubeCtl.Apply_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    Get_VPP_Status
    ${status1}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=4444    udp_port=5000
    ${status2}=    BuiltIn.Run_Keyword_And_Return_Status    Get_Traffic_Status    ${policy_name}    tcp_port=5000    udp_port=7000
    KubeCtl.Delete_F    ${testbed_connection}    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}.yaml
    BuiltIn.Should_Be_True    ${status1} and ${status2}




*** Keywords ***
Test_Case_Setup
    Setup_Hosts_Connections

Test_Case_Teardown
    Get_VPP_Status
    Teardown_Hosts_Connections

Get_VPP_Status
    Sleep    3s
    Switch_And_Write_Command    ${vpp_connection}    show acl-plugin acl
    Switch_And_Write_Command    ${vpp_connection}    show session rules tcp 
    Switch_And_Write_Command    ${vpp_connection}    show session rules udp

Get_Traffic_Status
    [Arguments]    ${policy_name}    ${tcp_port}=4444    ${udp_port}=7000
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
    ${expected}=    OperatingSystem.Get_File    ${CURDIR}/${TEST_DATA_FOLDER}/${policy_name}_tcp_${tcp_port}_udp_${udp_port}_expected.txt
    Log    ${expected}
    BuiltIn.Should_Be_Equal    ${report}    ${expected}

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
    [Documentation]    Open and store two more SSH connections to master host, in them open
    ...    pod shells to client and server pod, parse their IP addresses and store them.
    EnvConnections.Open_Client_Connection
    EnvConnections.Open_Server_Connection
    EnvConnections.Open_VPP_Connection

Teardown_Hosts_Connections
    [Documentation]    Exit pod shells, close corresponding SSH connections.
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${client_connection}
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${server_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
    SSHLibrary.Switch_Connection    ${server_connection}
    SSHLibrary.Close_Connection
    SSHLibrary.Switch_Connection    ${vpp_connection}
    SSHLibrary.Close_Connection

