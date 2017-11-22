*** Settings ***
Documentation     Test suite to test basic ping, udp, tcp and dns functionality of the network plugin.
Resource          ${CURDIR}/../libraries/all_libs.robot
Suite Setup       TwoNodesK8sSetup
Suite Teardown    TwoNodesK8sTeardown

*** Test Cases ***
#Pod_To_Ten_Nginxs
#    [Documentation]    Curl from one pod to another. Pods are on different nodes.
#    [Setup]    Setup_Hosts_Connections
#    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    curl http://${nginx_ip}    ssh_session=${client_connection}
#    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed
#    [Teardown]    Teardown_Hosts_Connections

Host_To_Ten_Nginxs
    [Documentation]    Curl from linux host pod to another on the same node
    Log    ${nginx_list}
    : FOR    ${nginx_node}     IN     @{nginx_list}
    \    ${nginx_node_details} =    KubeCtl.Describe_Pod    ${testbed_connection}    ${nginx_node}
    \    ${nginx_node_ip} =    BuiltIn.Evaluate    &{nginx_node_details}[${nginx_node}]["IP"]
    \    ${stdout} =    KubernetesEnv.Execute_Command_And_Log_All    ${testbed_connection}    curl http://${nginx_node_ip} --noproxy ${nginx_node_ip}   ignore_stderr=${True}
    \    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed

*** Keywords ***
TwoNodesK8sSetup
    Testsuite Setup
    KubernetesEnv.Reinit_Multi_Node_Kube_Cluster
    KubernetesEnv.Deploy_Client_Pod_And_Verify_Running    ${testbed_connection}    client_file=${CLIENT_POD_FILE}
    KubernetesEnv.Deploy_Multireplica_Pods_And_Verify_Running    ${testbed_connection}    ${NGINX_10_POD_FILE}    nginx-    10
    ${client_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${client_ip} =     BuiltIn.Evaluate    &{client_pod_details}[${client_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${client_ip}
    ${nginx_list} =    KubernetesEnv.Get_Pod_Name_List_By_Prefix    ${testbed_connection}    nginx-
    BuiltIn.Set_Suite_Variable    ${nginx_list}

TwoNodesK8sTeardown
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}
    KubernetesEnv.Remove_Client_Pod_And_Verify_Removed    ${testbed_connection}    client_file=${CLIENT_POD_FILE_NODE1}
    KubernetesEnv.Remove_Multireplica_Pods_And_Verify_Removed    ${testbed_connection}    ${NGINX_10_POD_FILE}    nginx-
    Testsuite Teardown

Setup_Hosts_Connections
    [Arguments]    ${user}=localadmin    ${password}=cisco123
    ${conn} =     SSHLibrary.Get_Connection    ${testbed_connection}
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${client_connection}    ${client_pod_name}    prompt=#

Teardown_Hosts_Connections
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${client_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
