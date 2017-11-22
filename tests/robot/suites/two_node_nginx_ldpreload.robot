*** Settings ***
Documentation     Test suite to test plugin by using ldpreloaded nginx.
Resource          ${CURDIR}/../libraries/KubernetesEnv.robot
Resource          ${CURDIR}/../libraries/setup-teardown.robot
Suite Setup       TwoNodesK8sSetup
Suite Teardown     TwoNodesK8sTeardown

*** Variables ***
${VARIABLES}          common
${ENV}                common
${NGNIX_FILE}         ${CURDIR}/../resources/nginx-ldpreload-node2.yaml
${CLIENT_FILE}        ${CURDIR}/../resources/ubuntu-client-ldpreload-node1.yaml



*** Test Cases ***
Pod_To_Nginx
    [Documentation]    Curl from one pod to another. Pods are on different nodes.
    [Setup]    Setup_Hosts_Connections
    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    curl http://${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed
    [Teardown]    Teardown_Hosts_Connections

Host_To_Nginx
    [Documentation]    Curl from linux host pod to another on the same node
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    curl http://${nginx_ip} --noproxy ${nginx_ip}   ignore_stderr=${True}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed

*** Keywords ***
TwoNodesK8sSetup
    Testsuite Setup
    KubernetesEnv.Reinit_Multi_Node_Kube_Cluster
    KubernetesEnv.Deploy_Client_Pod_And_Verify_Running    ${testbed_connection}    client_file=${CLIENT_FILE}
    KubernetesEnv.Deploy_Nginx_Pod_And_Verify_Running    ${testbed_connection}    nginx_file=${NGNIX_FILE}
    ${client_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${nginx_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${nginx_pod_name}
    ${client_ip} =     BuiltIn.Evaluate    &{client_pod_details}[${client_pod_name}]["IP"]
    ${nginx_ip} =     BuiltIn.Evaluate    &{nginx_pod_details}[${nginx_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${client_ip}
    BuiltIn.Set_Suite_Variable    ${nginx_ip}

TwoNodesK8sTeardown
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}
    KubernetesEnv.Remove_Nginx_Pod_And_Verify_Removed    ${testbed_connection}    nginx_file=${NGNIX_FILE}
    KubernetesEnv.Remove_Client_Pod_And_Verify_Removed    ${testbed_connection}    client_file=${CLIENT_FILE}
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
