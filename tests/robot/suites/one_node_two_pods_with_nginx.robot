*** Settings ***
Documentation     This suite simply deploy pod and delete it.
Resource     ${CURDIR}/../libraries/KubeCtl.robot
Resource     ${CURDIR}/../variables/${VARIABLES}_variables.robot
Resource     ${CURDIR}/../libraries/all_libs.robot
Suite Setup       BuiltIn.Run_Keywords     Testsuite Setup    AND    Store_Initial_Variables
Suite Teardown    Testsuite Teardown

*** Variables ***
${UBUNTU_POD_FILE}    ${CURDIR}/../resources/one-ubuntu-istio.yaml
${NGINX_POD_FILE}    ${CURDIR}/../resources/nginx-istio.yaml
${ISTIO_FILE}    ${CURDIR}/../resources/istio029.yaml
${VARIABLES}          common
${ENV}                common
${PLUGIN_URL}    https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml

*** Test Cases ***
Docker_Pull_Contiv_Vpp
    Execute_Command_And_Log_All    ${testbed_connection}    bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/pull-images.sh)

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

Deploy_Ubuntu_Pod
    KubeCtl.Apply_F    ${testbed_connection}    ${UBUNTU_POD_FILE}
    ${ubuntu_list} =    KubeCtl.Get_Pod_Name_By_Prefix    ${testbed_connection}    ubuntu-
    ${ubuntu_list} =    BuiltIn.Wait_Until_Keyword_Succeeds    10s    2s    Get_Pod_Name    ${testbed_connection}    ubuntu-    ${1}
    BuiltIn.Set_Suite_Variable    ${client_pod_name}    @{ubuntu_list}[0]
    KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    ${client_pod_name}    timeout=60s

Deploy_Nginx_Pod
    KubeCtl.Apply_F    ${testbed_connection}    ${NGINX_POD_FILE}
    ${nginx_list} =    KubeCtl.Get_Pod_Name_By_Prefix    ${testbed_connection}    nginx-
    ${nginx_list} =    BuiltIn.Wait_Until_Keyword_Succeeds    10s    2s    Get_Pod_Name    ${testbed_connection}    nginx-    ${1}
    BuiltIn.Set_Suite_Variable    ${nginx_pod_name}    @{nginx_list}[0]
    KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    ${nginx_pod_name}    timeout=60s

Ping
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    Run_Finite_Command    ping -c 5 ${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]     Teardown_Client_Pod_Session

Get_Web_Page
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    Run_Finite_Command    curl -vv http://${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    Welcome to nginx
    [Teardown]    Teardown_Client_Pod_Session

Delete_Nginx_Pod
    KubeCtl.Delete_F    ${testbed_connection}    ${NGINX_POD_FILE}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${nginx_pod_name}

Delete_Ubuntu_Pod
    KubeCtl.Delete_F    ${testbed_connection}    ${UBUNTU_POD_FILE}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${client_pod_name}

Deploy_Istio_Itself
    KubeCtl.Apply_F    ${testbed_connection}    ${ISTIO_FILE}
    ${istio_list} =    KubeCtl.Get_Pod_Name_By_Prefix    ${testbed_connection}    istio-
    : FOR    ${istio_item}    IN    @{istio_list}
    \     KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    ${istio_item}    timeout=60s    namespace=istio-system

Deploy_Ubuntu_Pod_Istio
    KubeCtl.Apply_F    ${testbed_connection}    ${UBUNTU_POD_FILE}
    ${ubuntu_list} =    KubeCtl.Get_Pod_Name_By_Prefix    ${testbed_connection}    ubuntu-
    ${ubuntu_list} =    BuiltIn.Wait_Until_Keyword_Succeeds    10s    2s    Get_Pod_Name    ${testbed_connection}    ubuntu-    ${1}
    BuiltIn.Set_Suite_Variable    ${client_pod_name}    @{ubuntu_list}[0]
    KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    ${client_pod_name}    timeout=60s

Deploy_Nginx_Pod_Istio
    KubeCtl.Apply_F    ${testbed_connection}    ${NGINX_POD_FILE}
    ${nginx_list} =    KubeCtl.Get_Pod_Name_By_Prefix    ${testbed_connection}    nginx-
    ${nginx_list} =    BuiltIn.Wait_Until_Keyword_Succeeds    10s    2s    Get_Pod_Name    ${testbed_connection}    nginx-    ${1}
    BuiltIn.Set_Suite_Variable    ${nginx_pod_name}    @{nginx_list}[0]
    KubeCtl.Wait_Until_Pod_Started    ${testbed_connection}    ${nginx_pod_name}    timeout=60s

Ping_Istio
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    Run_Finite_Command    ping -c 5 ${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    5 received, 0% packet loss
    [Teardown]     Teardown_Client_Pod_Session

Get_Web_Page_Istio
    [Setup]    Setup_Client_Pod_Session
    ${stdout} =    Run_Finite_Command    curl -vv http://${nginx_ip}    ssh_session=${client_connection}
    BuiltIn.Should_Contain   ${stdout}    Welcome to nginx
    [Teardown]    Teardown_Client_Pod_Session

Delete_Nginx_Pod_Istio
    KubeCtl.Delete_F    ${testbed_connection}    ${NGINX_POD_FILE}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${nginx_pod_name}

Delete_Ubuntu_Pod_Istio
    KubeCtl.Delete_F    ${testbed_connection}    ${UBUNTU_POD_FILE}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${client_pod_name}

Delete_Istio_Itself
    ${istio_list} =    KubeCtl.Get_Pod_Name_By_Prefix    ${testbed_connection}    istio-
    BuiltIn.Run_Keyword_And_Ignore_Error    KubeCtl.Delete_F    ${testbed_connection}    ${ISTIO_FILE}
    : FOR    ${istio_item}    IN    @{istio_list}
    \     KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${istio_item}    namespace=istio-system

Delete_Network_Plugin
    KubeCtl.Delete_F_Url    ${testbed_connection}    ${PLUGIN_URL}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${etcd_pod}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${vswitch_pod}
    KubeCtl.Wait_Until_Pod_Removed    ${testbed_connection}    ${ksr_pod}

*** Keywords ***
Store_Initial_Variables
     ${conn} =     SSHLibrary.Get_Connection
     Set_Suite_Variable    ${testbed_connection}    ${conn.index}

Setup_Client_Pod_Session
    [Arguments]    ${user}=localadmin    ${password}=cisco123
    ${conn} =     SSHLibrary.Get_Connection    ${testbed_connection}
    ${client_connection} =    SSHLibrary.Open_Connection    ${conn.host}    timeout=10
    SSHLibrary.Login    ${user}    ${password}
    BuiltIn.Set_Suite_Variable    ${client_connection}
    Get_Into_Container_Prompt    ${client_connection}    ${client_pod_name}    prompt=#
    ${client_pod_details} =     Describe_Pod    ${testbed_connection}    ${client_pod_name}
    ${client_ip} =     BuiltIn.Evaluate    &{client_pod_details}[${client_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${client_ip}
    ${nginx_pod_details} =     Describe_Pod    ${testbed_connection}    ${nginx_pod_name}
    ${nginx_ip} =     BuiltIn.Evaluate    &{nginx_pod_details}[${nginx_pod_name}]["IP"]
    BuiltIn.Set_Suite_Variable    ${nginx_ip}

Teardown_Client_Pod_Session
    Leave_Container_Prompt    ${client_connection}
    SSHLibrary.Switch_Connection    ${client_connection}
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

Get_Pod_Name
    [Arguments]     ${ssh_session}    ${prefix}    ${exp_count}
    ${pod_list} =    KubeCtl.Get_Pod_Name_By_Prefix    ${ssh_session}    ${prefix}
    BuiltIn.Length_Should_Be    ${pod_list}    ${exp_count}
    BuiltIn.Return_From_Keyword    ${pod_list}
