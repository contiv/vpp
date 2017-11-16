*** Settings ***
Documentation     Test suite to test basic ping, udp, tcp and dns functionality of the network plugin in 2 host setup.
Resource          ${CURDIR}/../libraries/KubernetesEnv.robot
Resource          ${CURDIR}/../variables/${VARIABLES}_variables.robot
Resource          ${CURDIR}/../libraries/setup-teardown.robot
Suite Setup       TwoNodesK8sSetup
Suite Teardown    TwoNodesK8sTeardown

*** Variables ***
${VARIABLES}          common
${ENV}                common

*** Test Cases ***
Pod_To_Pod_Ping
    [Documentation]    Pod to pod ping, pods are on different nodes.
    [Setup]    Setup_Hosts_Connections
    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${server_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
#    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${client_ip}    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]    Teardown_Hosts_Connections

#Pod_To_Pod_Udp
#    [Documentation]    Pod to pod udp, pods are on different nodes.
#    [Setup]    Setup_Hosts_Connections
#    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -ul -p 7000    ssh_session=${server_connection}
#    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${server_ip} 7000    ssh_session=${client_connection}
#    ${text} =    BuiltIn.Set_Variable    Text to be received
#    SSHLibrary.Write    ${text}
#    ${client_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
#    ${server_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
#    [Teardown]    Teardown_Hosts_Connections

#Pod_To_Pod_Tcp
#    [Documentation]    Pod to pod tcp, pods are on different nodes.
#    [Setup]    Setup_Hosts_Connections
#    ${text} =    BuiltIn.Set_Variable    Text to be received
#    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${client_connection}
#    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p 4444    ssh_session=${server_connection}
#    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${server_ip} 4444 < some.file    ssh_session=${client_connection}
#    ${server_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
#    ${client_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${client_connection}
#    [Teardown]    Teardown_Hosts_Connections

Host_To_Pod_Ping
    [Documentation]    Host to pod ping, client_ip is local, server_ip is remote
    [Setup]    Setup_Hosts_Connections
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    ping -c 5 ${server_ip}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    ping -c 5 ${client_ip}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]    Teardown_Hosts_Connections

#Host_To_Pod_Udp_Remote
#    [Documentation]    Host to pod udp, dst pod runs on a different nodes.
#    [Setup]    Setup_Hosts_Connections
#    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -ul -p 7000    ssh_session=${server_connection}
#    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -u ${server_ip} 7000    ssh_session=${testbed_connection}
#    ${text} =    BuiltIn.Set_Variable    Text to be received
#    SSHLibrary.Write    ${text}
#    ${client_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$
#    ${server_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
#    [Teardown]    Teardown_Hosts_Connections

#Host_To_Pod_Tcp_Remote
#    [Documentation]    Host to pod tcp, dst pod runs on a different nodes.
#    [Setup]    Setup_Hosts_Connections
#    ${text} =    BuiltIn.Set_Variable    Text to be received
#    KubernetesEnv.Run_Finite_Command_In_Pod    cd; echo "${text}" > some.file    ssh_session=${testbed_connection}
#    KubernetesEnv.Init_Infinite_Command_in_Pod    nc -l -p 4444    ssh_session=${server_connection}
#    KubernetesEnv.Init_Infinite_Command_in_Pod    cd; nc ${server_ip} 4444 < some.file    ssh_session=${testbed_connection}
#    ${server_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${server_stdout}    ${text}
#    ${client_stdout} =    KubernetesEnv.Stop_Infinite_Command_In_Pod    ssh_session=${testbed_connection}    prompt=$
#    [Teardown]    Teardown_Hosts_Connections

#Pod_To_Nginx_Local
#    [Documentation]    Curl from one pod to another on the same node. Server_pod is just a ubuntu pod running on the same
#    ...    same node as nxinf pod.
#    [Setup]    Setup_Hosts_Connections
#    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    curl http://${nginx_ip}    ssh_session=${server_connection}
#    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed
#    [Teardown]    Teardown_Hosts_Connections

Pod_To_Nginx_Remote
    [Documentation]    Curl from one pod to another. Pods are on different nodes.
    [Setup]    Setup_Hosts_Connections
    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    curl http://${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed
    [Teardown]    Teardown_Hosts_Connections

Host_To_Nginx_Local
    [Documentation]    Curl from linux host pod to another on the same node
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${VM_SSH_ALIAS_PREFIX}2    curl http://${nginx_ip} --noproxy ${nginx_ip}   ignore_stderr=${True}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed

Host_To_Nginx_Remote
    [Documentation]    Curl from linux host to pod on another node
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${VM_SSH_ALIAS_PREFIX}1    curl http://${nginx_ip} --noproxy ${nginx_ip}    ignore_stderr=${True}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed

*** Keywords ***
TwoNodesK8sSetup
    [Documentation]    Execute common setup, reinit 2node cluster, deploy client, server and nginx pods,
    ...    parse and store their IP addresses.
    setup-teardown.Testsuite_Setup
    KubernetesEnv.Reinit_Multi_Node_Kube_Cluster
    KubernetesEnv.Deploy_Client_Pod_And_Verify_Running    ${testbed_connection}    client_file=${CLIENT_POD_FILE_NODE1}
    KubernetesEnv.Deploy_Server_Pod_And_Verify_Running    ${testbed_connection}    server_file=${SERVER_POD_FILE_NODE2}
    KubernetesEnv.Deploy_Nginx_Pod_And_Verify_Running    ${testbed_connection}    nginx_file=${NGINX_POD_FILE_NODE2}
    ${client_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${server_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${server_pod_name}
    ${nginx_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${nginx_pod_name}
    ${server_ip} =     BuiltIn.Evaluate    &{server_pod_details}[${server_pod_name}]["IP"]
    ${client_ip} =     BuiltIn.Evaluate    &{client_pod_details}[${client_pod_name}]["IP"]
    ${nginx_ip} =     BuiltIn.Evaluate    &{nginx_pod_details}[${nginx_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${server_ip}
    BuiltIn.Set_Suite_Variable    ${client_ip}
    BuiltIn.Set_Suite_Variable    ${nginx_ip}

TwoNodesK8sTeardown
    [Documentation]    Log leftover output from pods, remove pods, execute common teardown.
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}    exp_nr_vswitch=2
    KubernetesEnv.Remove_Nginx_Pod_And_Verify_Removed    ${testbed_connection}    nginx_file=${NGINX_POD_FILE_NODE2}
    KubernetesEnv.Remove_Client_Pod_And_Verify_Removed    ${testbed_connection}    client_file=${CLIENT_POD_FILE_NODE1}
    KubernetesEnv.Remove_Server_Pod_And_Verify_Removed    ${testbed_connection}    server_file=${SERVER_POD_FILE_NODE2}
    setup-teardown.Testsuite_Teardown

Setup_Hosts_Connections
    [Arguments]    ${user}=localadmin    ${password}=cisco123
    [Documentation]    Open and store two more SSH connections to master host, in one of them open
    ...    pod shell to client pod.
    Builtin.Log_Many    ${user}    ${password}
    ${conn} =     SSHLibrary.Get_Connection    ${testbed_connection}
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    ${server_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${server_connection}
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${client_connection}    ${client_pod_name}    prompt=#
#    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${server_connection}    ${server_pod_name}    prompt=#

Teardown_Hosts_Connections
    [Documentation]    Exit client pod shell, close both new SSH connections.
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${client_connection}
#    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${server_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
    SSHLibrary.Switch_Connection    ${server_connection}
    SSHLibrary.Close_Connection
