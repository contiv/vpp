*** Settings ***
Documentation     This suite test getting the web page from nginx (without istio).
Resource          ${CURDIR}/../libraries/all_libs.robot
Suite Setup       OneNodeK8sSetup
Suite Teardown    OneNodeK8sTeardown

*** Test Cases ***
Pod_To_Nginx_Ping
    [Documentation]    Execute "ping -c 5" from client pod to nginx IP address, check zero packet loss.
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    ping -c 5 ${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]     Teardown_Client_Pod_Session

Host_To_Nginx_Ping
    [Documentation]    Execute "ping -c 5" from host to nginx IP address, check zero packet loss.
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    ping -c 5 ${nginx_ip}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss

Get_Web_Page_From_Pod
    [Documentation]    Execute curl from client pod to nginx IP address, check the expected response is seen.
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    KubernetesEnv.Run_Finite_Command_In_Pod    curl http://${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed
    [Teardown]    Teardown_Client_Pod_Session

Get_Web_Page_From_Host
    [Documentation]    Execute curl from host to nginx IP address, check the expected response is seen.
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    curl http://${nginx_ip} --noproxy ${nginx_ip}    ignore_stderr=${True}
    BuiltIn.Should_Contain   ${stdout}    If you see this page, the nginx web server is successfully installed

*** Keywords ***
OneNodeK8sSetup
    [Documentation]    Execute common setup, reinit 1node cluster, deploy client and nginx pods.
    setup-teardown.Testsuite_Setup
    KubernetesEnv.Reinit_One_Node_Kube_Cluster
    KubernetesEnv.Deploy_Client_And_Nginx_Pod_And_Verify_Running    ${testbed_connection}

OneNodeK8sTeardown
    [Documentation]    Log leftover output from pods, remove pods, execute common teardown.
    KubernetesEnv.Log_Pods_For_Debug    ${testbed_connection}    exp_nr_vswitch=1
    KubernetesEnv.Remove_Client_And_Nginx_Pod_And_Verify_Removed    ${testbed_connection}
    setup-teardown.Testsuite_Teardown

Setup_Client_Pod_Session
    [Arguments]    ${user}=localadmin    ${password}=cisco123
    [Documentation]    Open and store one more SSH connection to master host, in it open
    ...    pod shell to client pod, parse IP addresses for client and nginx and store them.
    Builtin.Log_Many    ${user}    ${password}
    Builtin.Comment    FIXME: De-duplicate into a Resource.
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
    [Documentation]    Exit client pod shell, close corresponding SSH connection.
    KubernetesEnv.Leave_Container_Prompt_In_Pod    ${client_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
    SSHLibrary.Close_Connection
