*** Settings ***
Documentation     This suite test getting the web page from nginx
Resource     ${CURDIR}/../libraries/KubernetesEnv.robot
Resource     ${CURDIR}/../variables/${VARIABLES}_variables.robot
Resource     ${CURDIR}/../libraries/all_libs.robot
Suite Setup       OneNodeK8sSetup
Suite Teardown     OneNodeK8sTeardown

*** Variables ***
${VARIABLES}          common
${ENV}                common

*** Test Cases ***
Pod_To_Nginx_Ping
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]     Teardown_Client_Pod_Session

Host_To_Nginx_Ping
    ${stdout} =    KubernetesEnv.Execute_Command_And_Log_All    ${testbed_connection}    ping -c 5 ${nginx_ip}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss

Get_Web_Page_From_Pod
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    curl http://${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed
    [Teardown]    Teardown_Client_Pod_Session

Get_Web_Page_From_Host
    ${stdout} =    KubernetesEnv.Execute_Command_And_Log_All    ${testbed_connection}    curl http://${nginx_ip} --noproxy ${nginx_ip}    ignore_stderr=${True}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed

*** Keywords ***
OneNodeK8sSetup
    Testsuite Setup
    KubernetesEnv.Reinit_One_Node_Kube_Cluster
    KubernetesEnv.Deploy_Client_And_Nginx_Pod_And_Verify_Running    ${testbed_connection}

OneNodeK8sTeardown
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}
    KubernetesEnv.Remove_Client_And_Nginx_Pod_And_Verify_Removed    ${testbed_connection}
    Testsuite Teardown

Setup_Client_Pod_Session
    [Arguments]    ${user}=localadmin    ${password}=cisco123
    ${conn} =     SSHLibrary.Get_Connection    ${testbed_connection}
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    KubernetesEnv.Get_Into_Container_Prompt_In_Pod    ${client_connection}    ${client_pod_name}    prompt=#
    ${client_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${nginx_pod_details} =     KubeCtl.Describe_Pod    ${testbed_connection}    ${nginx_pod_name}
    ${nginx_ip} =     BuiltIn.Evaluate    &{nginx_pod_details}[${nginx_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${nginx_ip}

Teardown_Client_Pod_Session
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${client_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
