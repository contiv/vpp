*** Settings ***
Documentation     This suite simply deploy pod and delete it.
Resource     ${CURDIR}/../libraries/KubeCtl.robot
Resource     ${CURDIR}/../variables/${VARIABLES}_variables.robot
Resource     ${CURDIR}/../libraries/all_libs.robot
Suite Setup       BuiltIn.Run_Keywords     Testsuite Setup    AND    Store_And_Set_Initial_Variables
Suite Teardown    Testsuite Teardown

*** Variables ***
${POD_FILE}    ${CURDIR}/../resources/ubuntu.yaml
${VARIABLES}          common
${ENV}                common
${PLUGIN_URL}    https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml

*** Test Cases ***
Docker_Pull_Ksr
    Execute_Command_And_Log_All    ${testbed_connection}    docker pull contivvpp/ksr:latest

Docker_Pull_Cni
    Execute_Command_And_Log_All    ${testbed_connection}    docker pull contivvpp/cni:latest

Docker_Pull_Vswitch
    Execute_Command_And_Log_All    ${testbed_connection}    docker pull contivvpp/vswitch:latest

Apply Network Plugin
    KubeCtl.Apply_F_Url    ${testbed_connection}    ${PLUGIN_URL}
    ${etcd_pod_list} =     KubeCtl.Get_Pod_Name_By_Prefix   ${testbed_connection}    contiv-etcd-
    BuiltIn.Length_Should_Be    ${etcd_pod_list}    1
    KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    @{etcd_pod_list}[0]    namespace=kube-system
    BuiltIn.Set_Suite_Variable    ${etcd_pod}    @{etcd_pod_list}[0]
    ${ksr_pod_list} =     KubeCtl.Get_Pod_Name_By_Prefix   ${testbed_connection}    contiv-ksr-
    BuiltIn.Length_Should_Be    ${ksr_pod_list}     1
    KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    @{ksr_pod_list}[0]    namespace=kube-system
    BuiltIn.Set_Suite_Variable    ${ksr_pod}    @{ksr_pod_list}[0]
    ${vswitch_pod_list} =     KubeCtl.Get_Pod_Name_By_Prefix   ${testbed_connection}    contiv-vswitch-
    BuiltIn.Length_Should_Be    ${vswitch_pod_list}     1
    KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    @{vswitch_pod_list}[0]    namespace=kube-system
    BuiltIn.Set_Suite_Variable    ${vswitch_pod}    @{vswitch_pod_list}[0]

Deploy_Pods
    KubeCtl.Apply_F    ${testbed_connection}    ${POD_FILE}
    ${pods_dict} =     KubeCtl.Get_Pods    ${testbed_connection}
    BuiltIn.Log      ${pods_dict}
    BuiltIn.Length_Should_Be    ${pods_dict}    2
    ${pod_names} =    Collections.Get_Dictionary_Keys    ${pods_dict}
    : FOR    ${pod_name}   IN    @{pod_names}
    \     KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    ${pod_name}

Pod_To_Pod_Ping
    [Setup]    Setup_Hosts_Connections
    ${stdout} =    Run_Finite_Command    ping -c 5 ${server_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${stdout} =    Run_Finite_Command    ping -c 5 ${client_ip}    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]    Teardown_Hosts_Connections

Pod_To_Pod_Udp
    [Setup]    Setup_Hosts_Connections
    Init_Infinite_Command    nc -ul -p 7000    ssh_session=${server_connection}
    Init_Infinite_Command    nc -u ${server_ip} 7000    ssh_session=${client_connection}
    ${text} =    BuiltIn.Set_Variable    Text to be received
    SSHLibrary.Write    ${text}
    ${client_stdout} =    Stop_Infinite_Command    ssh_session=${client_connection}
    ${server_stdout} =    Stop_Infinite_Command    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    [Teardown]    Teardown_Hosts_Connections

Pod_To_Pod_Tcp
    [Setup]    Setup_Hosts_Connections
    ${text} =    BuiltIn.Set_Variable    Text to be received
    Run_Finite_Command    cd; echo "${text}" > some.file    ssh_session=${client_connection}
    Init_Infinite_Command    nc -l -p 4444    ssh_session=${server_connection}
    Init_Infinite_Command    cd; nc ${server_ip} 4444 < some.file    ssh_session=${client_connection}
    ${server_stdout} =    Stop_Infinite_Command    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${client_stdout} =    Stop_Infinite_Command    ssh_session=${client_connection}
    [Teardown]    Teardown_Hosts_Connections

Pod_To_Pod_Dns
    [Setup]    Setup_Hosts_Connections
    ${stdout} =    Run_Finite_Command    ping -c 5 ${server_pod_name}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${stdout} =    Run_Finite_Command    ping -c 5 ${client_pod_name}    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]    Teardown_Hosts_Connections

Host_To_Pod_Ping
    [Setup]    Setup_Hosts_Connections
    ${stdout} =    Run_Finite_Command    ping -c 5 ${server_ip}    ssh_session=${testbed_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${stdout} =    Run_Finite_Command    ping -c 5 ${client_ip}    ssh_session=${testbed_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]    Teardown_Hosts_Connections

Host_To_Pod_Udp
    [Setup]    Setup_Hosts_Connections
    Init_Infinite_Command    nc -ul -p 7000    ssh_session=${server_connection}
    Init_Infinite_Command    nc -u ${server_ip} 7000    ssh_session=${testbed_connection}
    ${text} =    BuiltIn.Set_Variable    Text to be received
    SSHLibrary.Write    ${text}
    ${client_stdout} =    Stop_Infinite_Command    ssh_session=${testbed_connection}
    ${server_stdout} =    Stop_Infinite_Command    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    [Teardown]    Teardown_Hosts_Connections

Host_To_Pod_Tcp
    [Setup]    Setup_Hosts_Connections
    ${text} =    BuiltIn.Set_Variable    Text to be received
    Run_Finite_Command    cd; echo "${text}" > some.file    ssh_session=${testbed_connection}
    Init_Infinite_Command    nc -l -p 4444    ssh_session=${server_connection}
    Init_Infinite_Command    cd; nc ${server_ip} 4444 < some.file    ssh_session=${testbed_connection}
    ${server_stdout} =    Stop_Infinite_Command    ssh_session=${server_connection}
    BuiltIn.Should_Contain   ${server_stdout}    ${text}
    ${client_stdout} =    Stop_Infinite_Command    ssh_session=${testbed_connection}
    [Teardown]    Teardown_Hosts_Connections

Host_To_Pod_Dns
    ${stdout} =    Execute_Command_And_Log_All    ${testbed_connection}    ping -c 5 ${server_pod_name}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${stdout} =    Execute_Command_And_Log_All    ${testbed_connection}    ping -c 5 ${client_pod_name}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss

Delete_Pods
    KubeCtl.Delete_F    ${testbed_connection}    ${POD_FILE}
    ${pods_dict} =     KubeCtl.Get_Pods    ${testbed_connection}
    Log      ${pods_dict}
    BuiltIn.Length_Should_Be    ${pods_dict}    2
    ${pod_names} =    Collections.Get_Dictionary_Keys    ${pods_dict}
    : FOR    ${pod_name}   IN    @{pod_names}
    \     KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${pod_name}

Delete_Network_Plugin
    KubeCtl.Delete_F_Url    ${testbed_connection}    ${PLUGIN_URL}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${etcd_pod}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${vswitch_pod}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${ksr_pod}

*** Keywords ***
Store_And_Set_Initial_Variables
     ${conn} =     SSHLibrary.Get_Connection
     Set_Suite_Variable    ${testbed_connection}    ${conn.index}
     SSHLibrary.Set_Client_Configuration    timeout=10    prompt=$

Setup_Hosts_Connections
    [Arguments]    ${user}=localadmin    ${password}=cisco123
    ${conn} =     SSHLibrary.Get_Connection    ${testbed_connection}
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    ${server_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${server_connection}
    ${pods_dict} =     Get_Pods    ${testbed_connection}
    Log      ${pods_dict}
    BuiltIn.Length_Should_Be    ${pods_dict}    2
    ${pod_names} =     Collections.Get_Dictionary_Keys    ${pods_dict}
    BuiltIn.Set_Suite_Variable    ${client_pod_name}    @{pod_names}[0]
    BuiltIn.Set_Suite_Variable    ${server_pod_name}    @{pod_names}[1]
    Get_Into_Container_Prompt    ${client_connection}    @{pod_names}[0]    prompt=#
    Get_Into_Container_Prompt    ${server_connection}    @{pod_names}[1]    prompt=#
    ${client_pod_details} =     Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${server_pod_details} =     Describe_Pod    ${testbed_connection}    ${server_pod_name}
    ${server_ip} =     BuiltIn.Evaluate    &{server_pod_details}[${server_pod_name}]["IP"]
    ${client_ip} =     BuiltIn.Evaluate    &{client_pod_details}[${client_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${server_ip}
    BuiltIn.Set_Suite_Variable    ${client_ip}

Teardown_Hosts_Connections
    Leave_Container_Prompt    ${client_connection}
    Leave_Container_Prompt    ${server_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
    SSHLibrary.Switch_Connection    ${server_connection}
    SSHLibrary.Close_Connection

Execute_Command_And_Log_All
    [Arguments]    ${ssh_session}    ${command}    ${expected_rc}=0
    SSHLibrary.Switch_Connection    ${ssh_session}
    ${stdout}    ${stderr}    ${rc} =    SSHLibrary.Execute_Command    ${command}    return_stderr=True    return_rc=True
    BuiltIn.Log    ${stdout}
    BuiltIn.Log    ${stderr}
    BuiltIn.Log    ${rc}
    BuiltIn.Should_Be_Empty    ${stderr}
    BuiltIn.Should_Be_Equal_As_Numbers    ${rc}    ${expected_rc}
    BuiltIn.Return_From_Keyword    ${stdout}

Run_Finite_Command
    [Arguments]    ${command}     ${ssh_session}=${EMPTY}     ${prompt}=${EMPTY}
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    ${command}
    ${stdout} =     SSHLibrary.Read_Until_Prompt
    Log     ${stdout}
    BuiltIn.Return_From_Keyword    ${stdout}

Init_Infinite_Command
    [Arguments]    ${command}     ${ssh_session}=${EMPTY}     ${prompt}=${EMPTY}
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    ${command}

Stop_Infinite_Command
    [Arguments]    ${ssh_session}=${EMPTY}     ${prompt}=${EMPTY}
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    Write_Bare_Ctrl_C
    ${stdout} =     SSHLibrary.Read_Until_Prompt
    Log     ${stdout}
    BuiltIn.Return_From_Keyword    ${stdout}

Write_Bare_Ctrl_C
    [Documentation]    Construct ctrl+c character and SSH-write it (without endline) to the current SSH connection.
    ...    Do not read anything yet.
    ${ctrl_c} =    BuiltIn.Evaluate    chr(int(3))
    SSHLibrary.Write_Bare    ${ctrl_c}

Get_Into_Container_Prompt
    [Arguments]    ${ssh_session}    ${pod_name}    ${prompt}=${EMPTY}
    SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    kubectl exec -it ${pod_name} -- /bin/bash
    ${stdout} =     SSHLibrary.Read_Until_Prompt
    Log     ${stdout}

Leave_Container_Prompt
    [Arguments]     ${ssh_session}    ${prompt}=$
    SSHLibrary.Switch_Connection    ${ssh_session}
    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    exit
    ${stdout} =     SSHLibrary.Read_Until_Prompt
    Log     ${stdout}
