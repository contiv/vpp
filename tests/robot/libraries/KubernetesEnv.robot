*** Settings ***
Documentation     This is a library to handle actions related to kubernetes cluster,
...    such as kubernetes setup or rester, applying network plugin etc.
Library     Collections
Resource    ${CURDIR}/KubeCtl.robot
Resource    ${CURDIR}/KubeAdm.robot

*** Variables ***
${NV_PLUGIN_URL}    https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
${CLIENT_POD_FILE}    ${CURDIR}/../resources/ubuntu-client.yaml
${SERVER_POD_FILE}    ${CURDIR}/../resources/ubuntu-server.yaml
${NGINX_POD_FILE}    ${CURDIR}/../resources/nginx.yaml
${CLIENT_ISTIO_POD_FILE}    ${CURDIR}/../resources/one-ubuntu-istio.yaml
${NGINX_ISTIO_POD_FILE}    ${CURDIR}/../resources/nginx-istio.yaml
${ISTIO_FILE}    ${CURDIR}/../resources/istio029.yaml

*** Keywords ***
Reinit_One_Node_Kube_Cluster
    ${conn} =     SSHLibrary.Get_Connection
    Set_Suite_Variable    ${testbed_connection}    ${conn.index}
    SSHLibrary.Set_Client_Configuration    timeout=10    prompt=$
    Execute_Command_And_Log_All    ${testbed_connection}    sudo rm -rf ~/.kube
    KubeAdm.Reset    ${testbed_connection}
    Docker_Pull_Contiv_Vpp    ${testbed_connection}
    ${stdout} =    KubeAdm.Init    ${testbed_connection}
    BuiltIn.Should_Contain    ${stdout}    Your Kubernetes master has initialized successfully
    Execute_Command_And_Log_All    ${testbed_connection}    mkdir -p $HOME/.kube
    Execute_Command_And_Log_All    ${testbed_connection}    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    Execute_Command_And_Log_All    ${testbed_connection}    sudo chown $(id -u):$(id -g) $HOME/.kube/config
    KubeCtl.Taint    ${testbed_connection}    nodes --all node-role.kubernetes.io/master-
    Apply_Contive_Vpp_Plugin    ${testbed_connection}
    # Verify k8s and plugin are running
    BuiltIn.Wait_Until_Keyword_Succeeds    240s    10s    Verify_K8s_With_Plugin_Running    ${testbed_connection}

Reinit_Multinode_Kube_Cluster
    # check integrity of k8s cluster settings
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    BuiltIn.Run_Keyword_If    """${index}""" == """${1}""" and """${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_ROLE}""" != """master"""   FAIL    Node ${index} should be kubernetes master.
    \    BuiltIn.Run_Keyword_If    """${index}""" != """${1}""" and """${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_ROLE}""" != """slave"""   FAIL    Node ${index} should be kubernetes slave.
    # reset all nodes
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    ${connection} =    BuiltIn.Set_Variable    ${VM_SSH_ALIAS_PREFIX}${index}
    \    Execute_Command_And_Log_All    ${VM_SSH_ALIAS_PREFIX}${index}    sudo rm -rf ~/.kube
    \    KubeAdm.Reset    ${connection}
    \    Docker_Pull_Contiv_Vpp    ${connection}
    # init master
    ${connection} =    BuiltIn.Set_Variable    ${VM_SSH_ALIAS_PREFIX}1
    ${init_stdout} =    KubeAdm.Init    ${connection}
    BuiltIn.Should_Contain    ${init_stdout}    Your Kubernetes master has initialized successfully
    Execute_Command_And_Log_All    ${connection}    mkdir -p $HOME/.kube
    Execute_Command_And_Log_All    ${connection}    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    Execute_Command_And_Log_All    ${connection}    sudo chown $(id -u):$(id -g) $HOME/.kube/config
    KubeCtl.Taint    ${connection}    nodes --all node-role.kubernetes.io/master-
    Apply_Contive_Vpp_Plugin    ${connection}
    # Verify k8s and plugin are running
    BuiltIn.Wait_Until_Keyword_Succeeds    240s    10s    Verify_K8s_With_Plugin_Running    ${connection}
    # join other nodes
    ${join_cmd} =    kube_parser.get_join_from_kubeadm_init    ${init_stdout}
    :FOR    ${index}    IN RANGE    2    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    ${connection} =    BuiltIn.Set_Variable    ${VM_SSH_ALIAS_PREFIX}${index}
    \    Execute_Command_And_Log_All    ${connection}    sudo ${join_cmd}    ignore_stderr=${True}
    Wait_Until_Cluster_Ready    ${VM_SSH_ALIAS_PREFIX}1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}
    

Docker_Pull_Contiv_Vpp
    [Arguments]    ${ssh_session}
    Execute_Command_And_Log_All    ${ssh_session}    bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/pull-images.sh)

Apply_Contive_Vpp_Plugin
    [Arguments]    ${ssh_session}
    KubeCtl.Apply_F_Url    ${ssh_session}    ${NV_PLUGIN_URL}

Execute_Command_And_Log_All
    [Arguments]    ${ssh_session}    ${command}    ${expected_rc}=0    ${ignore_stderr}=${False}
    SSHLibrary.Switch_Connection    ${ssh_session}
    ${stdout}    ${stderr}    ${rc} =    SSHLibrary.Execute_Command    ${command}    return_stderr=True    return_rc=True
    BuiltIn.Log    ${stdout}
    BuiltIn.Log    ${stderr}
    BuiltIn.Log    ${rc}
    BuiltIn.Run_Keyword_Unless    ${ignore_stderr}    BuiltIn.Should_Be_Empty    ${stderr}
    BuiltIn.Should_Be_Equal_As_Numbers    ${rc}    ${expected_rc}
    BuiltIn.Return_From_Keyword    ${stdout}

Verify_All_Pods_Running
    [Arguments]    ${ssh_session}    ${excluded_pod_prefix}=invalid-pod-prefix-
    [Documentation]     Iterate over all pods of all namespaces and check running state
    ${all_pods_dict} =    KubeCtl.Get_Pods_All_Namespaces    ${ssh_session}
    ${pod_names} =    Collections.Get_Dictionary_Keys    ${all_pods_dict}
    : FOR    ${pod_name}   IN    @{pod_names}
    \     BuiltIn.Continue_For_Loop_If    """${excluded_pod_prefix}""" in """${pod_name}"""
    \     ${namesp} =    BuiltIn.Evaluate    &{all_pods_dict}[${pod_name}]['NAMESPACE']
    \     Verify_Pod_Running_And_Ready    ${ssh_session}    ${pod_name}    namespace=${namesp}

Verify_K8s_With_Plugin_Running
    [Arguments]    ${ssh_session}
    [Documentation]     We check for particular number of pods after init. May be later replaced with
    ...    more detailed asserts.
    ${all_pods_dict} =    KubeCtl.Get_Pods_All_Namespaces    ${ssh_session}
    BuiltIn.Length_Should_Be   ${all_pods_dict}     9
    Verify_All_Pods_Running    ${ssh_session}

Get_Pod_Name_List_By_Prefix
    [Arguments]    ${ssh_session}    ${pod_prefix}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods --all-namespaces
    ${output} =     kube_parser.parse_kubectl_get_pods_and_get_pod_name    ${stdout}    ${pod_prefix}
    BuiltIn.Return_From_Keyword    ${output}

Deploy_Client_And_Server_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}
    [Documentation]     Deploy two ubuntu pods and 
    ${client_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${CLIENT_POD_FILE}    ubuntu-client-
    ${server_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${SERVER_POD_FILE}    ubuntu-server-
    BuiltIn.Set_Suite_Variable    ${client_pod_name}
    BuiltIn.Set_Suite_Variable    ${server_pod_name}

Remove_Client_And_Server_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}
    KubeCtl.Delete_F    ${ssh_session}    ${CLIENT_POD_FILE}
    KubeCtl.Delete_F    ${ssh_session}    ${SERVER_POD_FILE}
    Wait_Until_Pod_Removed    ${ssh_session}    ${client_pod_name}
    Wait_Until_Pod_Removed    ${ssh_session}    ${server_pod_name}

Deploy_Client_And_Nginx_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}    ${nginx_file}=${NGINX_POD_FILE}
    [Documentation]     Deploy one ubuntu and one nginx pod
    ${client_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${client_file}    ubuntu-client-
    ${nginx_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${nginx_file}    nginx-
    BuiltIn.Set_Suite_Variable    ${client_pod_name}
    BuiltIn.Set_Suite_Variable    ${nginx_pod_name}

Remove_Client_And_Nginx_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}    ${nginx_file}=${NGINX_POD_FILE}
    KubeCtl.Delete_F    ${ssh_session}    ${client_file}
    KubeCtl.Delete_F    ${ssh_session}    ${nginx_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${client_pod_name}
    Wait_Until_Pod_Removed    ${ssh_session}    ${nginx_pod_name}

Verify_Istio_Running
    [Arguments]    ${ssh_session}
    [Documentation]     We check istio- pods are running
    ${istio_pods_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    istio
    BuiltIn.Length_Should_Be   ${istio_pods_list}     5
    : FOR    ${istio_pod_name}    IN    @{istio_pods_list}
    \    Verify_Pod_Running_And_Ready    ${ssh_session}    ${istio_pod_name}    namespace=istio-system
    BuiltIn.Return_From_Keyword    ${istio_pods_list}

Deploy_Istio_And_Verify_Running
    [Arguments]    ${ssh_session}
    [Documentation]     Deploy istio pod
    KubeCtl.Apply_F    ${ssh_session}    ${ISTIO_FILE}
    ${istio_pods} =    BuiltIn.Wait_Until_Keyword_Succeeds    30s    4s    Verify_Istio_Running    ${ssh_session}
    BuiltIn.Set_Suite_Variable    ${istio_pods}

Verify_Istio_Removed
    [Arguments]    ${ssh_session}
    [Documentation]     We check istio- pods are running
    ${istio_pods_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    istio
    BuiltIn.Length_Should_Be   ${istio_pods_list}     0

Remove_Istio_And_Verify_Removed
    [Arguments]    ${ssh_session}
    [Documentation]     Deploy istio pod
    KubeCtl.Delete_F    ${ssh_session}    ${ISTIO_FILE}    expected_rc=${1}    ignore_stderr=${True}
    BuiltIn.Wait_Until_Keyword_Succeeds    60s    5s    Verify_Istio_Removed    ${ssh_session}

Deploy_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${pod_file}     ${pod_prefix}
    KubeCtl.Apply_F    ${ssh_session}    ${pod_file}
    ${pod_name_list} =    BuiltIn.Wait_Until_Keyword_Succeeds    10s    2s    Get_Pod_Name_List_By_Prefix    ${ssh_session}    ${pod_prefix}
    BuiltIn.Length_Should_Be    ${pod_name_list}    1
    ${pod_name} =    BuiltIn.Evaluate     ${pod_name_list}[0]
    Wait_Until_Pod_Running    ${ssh_session}    ${pod_name}
    BuiltIn.Return_From_Keyword    ${pod_name}

Remove_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${pod_file}    ${pod_name}
    KubeCtl.Delete_F    ${ssh_session}    ${pod_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${pod_name}

Verify_Pod_Running_And_Ready
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    &{pods} =     KubeCtl.Get_Pods    ${ssh_session}    namespace=${namespace}
    ${status} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['STATUS']
    BuiltIn.Should_Be_Equal_As_Strings    ${status}    Running
    ${ready} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['READY']
    ${ready_containers}    ${out_of_containers} =    String.Split_String    ${ready}    separator=${/}    max_split=1
    BuiltIn.Should_Be_Equal_As_Strings    ${ready_containers}    ${out_of_containers}

Wait_Until_Pod_Running
    [Arguments]    ${ssh_session}    ${pod_name}    ${timeout}=30s    ${check_period}=5s    ${namespace}=default
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Running_And_Ready    ${ssh_session}    ${pod_name}    namespace=${namespace}

Verify_Pod_Not_Present
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    ${pods} =     Get_Pods    ${ssh_session}    namespace=${namespace}
    Collections.Dictionary_Should_Not_Contain_Key     ${pods}    ${pod_name}

Wait_Until_Pod_Removed
    [Arguments]    ${ssh_session}    ${pod_name}    ${timeout}=90s    ${check_period}=5s    ${namespace}=default
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Not_Present    ${ssh_session}    ${pod_name}    namespace=${namespace}

Run_Finite_Command_In_Pod
    [Arguments]    ${command}     ${ssh_session}=${EMPTY}     ${prompt}=${EMPTY}
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    ${command}
    ${stdout} =     SSHLibrary.Read_Until_Prompt
    Log     ${stdout}
    BuiltIn.Return_From_Keyword    ${stdout}

Init_Infinite_Command_In_Pod
    [Arguments]    ${command}     ${ssh_session}=${EMPTY}     ${prompt}=${EMPTY}
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    ${command}

Stop_Infinite_Command_In_Pod
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

Get_Into_Container_Prompt_In_Pod
    [Arguments]    ${ssh_session}    ${pod_name}    ${prompt}=${EMPTY}
    SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    kubectl exec -it ${pod_name} -- /bin/bash
    ${stdout} =     SSHLibrary.Read_Until_Prompt
    Log     ${stdout}

Leave_Container_Prompt_In_Pod
    [Arguments]     ${ssh_session}    ${prompt}=$
    SSHLibrary.Switch_Connection    ${ssh_session}
    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    Write_Bare_Ctrl_C
    SSHLibrary.Write    exit
    ${stdout} =     SSHLibrary.Read_Until_Prompt
    Log     ${stdout}

Verify_Cluster_Node_Ready
    [Arguments]     ${ssh_session}    ${node_name}
    ${nodes} =    KubeCtl.Get_Nodes    ${ssh_session}
    ${status} =    BuiltIn.Evaluate    &{nodes}[${node_name}]['STATUS']
    BuiltIn.Should_Be_Equal    ${status}    Ready
    BuiltIn.Return_From_Keyword    ${nodes}

Verify_Cluster_Ready
    [Arguments]     ${ssh_session}    ${nr_nodes}
    ${nodes} =    KubeCtl.Get_Nodes    ${ssh_session}
    BuiltIn.Length_Should_Be    ${nodes}    ${nr_nodes}
    ${names} =     Collections.Get_Dictionary_Keys     ${nodes}
    : FOR    ${name}    IN    @{names}
    \    Verify_Cluster_Node_Ready    ${ssh_session}    ${name}

Wait_Until_Cluster_Ready
    [Arguments]    ${ssh_session}    ${nr_nodes}    ${timeout}=180s    ${check_period}=5s
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Cluster_Ready    ${ssh_session}    ${nr_nodes}

Log_Contiv_Etcd
    [Arguments]    ${ssh_session}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    contiv-etcd-
    BuiltIn.Length_Should_Be    ${pod_list}    1
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system

Log_Contiv_Ksr
    [Arguments]    ${ssh_session}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    contiv-ksr-
    BuiltIn.Length_Should_Be    ${pod_list}    1
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system

Log_Contiv_Vswitch
    [Arguments]    ${ssh_session}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    contiv-vswitch-
    BuiltIn.Length_Should_Be    ${pod_list}    1
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=contiv-cni
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=contiv-vswitch

Log_Kube_Dns
    [Arguments]    ${ssh_session}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    kube-dns-
    BuiltIn.Length_Should_Be    ${pod_list}    1
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=kubedns
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=dnsmasq
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=sidecar

Log_Pods_For_Debug
    [Arguments]    ${ssh_session}
    Log_Contiv_Etcd    ${ssh_session}
    Log_Contiv_Ksr    ${ssh_session}
    Log_Contiv_Vswitch    ${ssh_session}
    Log_Kube_Dns    ${ssh_session}
