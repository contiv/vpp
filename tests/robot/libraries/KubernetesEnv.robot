*** Settings ***
Documentation     This is a library to handle actions related to kubernetes cluster,
...               such as kubernetes setup or rester, applying network plugin etc.
...
...               The code is aimed at few selected deployments:
...               A: 1-node 2-pod, client and server pods: no specific applications, test use pind and nc to check connectivity.
...               B: 1-node 2-pod, client and nginx pods: nginx runs a web server, client uses curl to check, otherwise as B.
...               C: 1-node 2-pod, client and server istio pods: As A but both pods contain istio proxy.
...               D: 1-node 2-pod, client and nginx istio pods: As B but both pods contain istio proxy.
...
...               This Resource manages the following suite variables:
...               ${testbed_connection} SSH connection index towards host in 1-node k8s cluster.
...               ${client_pod_name} client pod name assigned by k8s in 1-node 2-pod scenario.
...               ${server_pod_name} server pod name assigned by k8s in 1-node 2-pod scenario.
...               ${nginx_pod_name} nginx pod name assigned by k8s in 1-node 2-pod scenario.
...               ${istio_pods} list of pods matching istio prefix last seen running.
Resource          ${CURDIR}/all_libs.robot

*** Variables ***
${NV_PLUGIN_URL}    https://raw.githubusercontent.com/contiv/vpp/${BRANCH}/k8s/contiv-vpp.yaml
${CRI_INSTALL_URL}    https://raw.githubusercontent.com/contiv/vpp/${BRANCH}/k8s/cri-install.sh
${CLIENT_POD_FILE}    ${CURDIR}/../resources/ubuntu-client.yaml
${SERVER_POD_FILE}    ${CURDIR}/../resources/ubuntu-server.yaml
${NGINX_POD_FILE}    ${CURDIR}/../resources/nginx.yaml
${CLIENT_POD_FILE_NODE1}    ${CURDIR}/../resources/ubuntu-client-node1.yaml
${SERVER_POD_FILE_NODE2}    ${CURDIR}/../resources/ubuntu-server-node2.yaml
${NGINX_POD_FILE_NODE2}    ${CURDIR}/../resources/nginx-node2.yaml
${CLIENT_ISTIO_POD_FILE}    ${CURDIR}/../resources/one-ubuntu-istio.yaml
${NGINX_ISTIO_POD_FILE}    ${CURDIR}/../resources/nginx-istio.yaml
${ISTIO_FILE}    ${CURDIR}/../resources/istio029.yaml
${NGINX_10_POD_FILE}    ${CURDIR}/../resources/nginx10.yaml

*** Keywords ***
Reinit_One_Node_Kube_Cluster
    [Documentation]    Assuming active SSH connection, store its index, execute multiple commands to reinstall and restart 1node cluster, wait to see it running.
    ${normal_tag}    ${vpp_tag} =    Get_Docker_Tags
    ${conn} =     SSHLibrary.Get_Connection    ${VM_SSH_ALIAS_PREFIX}1
    Set_Suite_Variable    ${testbed_connection}    ${conn.index}
    SSHLibrary.Set_Client_Configuration    timeout=${SSH_TIMEOUT}    prompt=$
    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    sudo rm -rf $HOME/.kube
    KubeAdm.Reset    ${testbed_connection}
    Uninstall_Cri
    Docker_Pull_Contiv_Vpp    ${testbed_connection}
    Docker_Pull_Custom_Kube_Proxy    ${testbed_connection}
    Install_Cri    ${normal_tag}
    ${stdout} =    KubeAdm.Init    ${testbed_connection}
    BuiltIn.Should_Contain    ${stdout}    Your Kubernetes master has initialized successfully
    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    mkdir -p $HOME/.kube
    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    SshCommons.Switch_And_Execute_Command    ${testbed_connection}    sudo chown $(id -u):$(id -g) $HOME/.kube/config
    KubeCtl.Taint    ${testbed_connection}    nodes --all node-role.kubernetes.io/master-
    Apply_Contive_Vpp_Plugin    ${testbed_connection}    ${normal_tag}    ${vpp_tag}
    # Verify k8s and plugin are running
    BuiltIn.Wait_Until_Keyword_Succeeds    240s    10s    Verify_K8s_With_Plugin_Running    ${testbed_connection}

Reinit_Multinode_Kube_Cluster
    [Documentation]    Assuming SSH connections with known aliases are created, check roles, reset nodes, init master, wait to see it running, join other nodes, wait until cluster is ready.
    ${normal_tag}    ${vpp_tag} =    Get_Docker_Tags
    # check integrity of k8s cluster settings
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    BuiltIn.Run_Keyword_If    """${index}""" == """${1}""" and """${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_ROLE}""" != """master"""   BuiltIn.Fail    Node ${index} should be kubernetes master.
    \    BuiltIn.Run_Keyword_If    """${index}""" != """${1}""" and """${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_ROLE}""" != """slave"""   BuiltIn.Fail    Node ${index} should be kubernetes slave.
    # reset all nodes
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    ${connection} =    BuiltIn.Set_Variable    ${VM_SSH_ALIAS_PREFIX}${index}
    \    SshCommons.Switch_And_Execute_Command    ${connection}    sudo rm -rf ~/.kube
    \    KubeAdm.Reset    ${connection}
    \    SshCommons.Switch_And_Execute_Command    ${connection}    sudo modprobe uio_pci_generic
    \    Uninstall_Cri
    \    Docker_Pull_Contiv_Vpp    ${connection}
    \    Docker_Pull_Custom_Kube_Proxy    ${connection}
    \    Install_Cri    ${normal_tag}
    # init master
    ${connection} =    BuiltIn.Set_Variable    ${VM_SSH_ALIAS_PREFIX}1
    ${init_stdout} =    KubeAdm.Init    ${connection}
    BuiltIn.Should_Contain    ${init_stdout}    Your Kubernetes master has initialized successfully
    SshCommons.Switch_And_Execute_Command    ${connection}    mkdir -p $HOME/.kube
    SshCommons.Switch_And_Execute_Command    ${connection}    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    SshCommons.Switch_And_Execute_Command    ${connection}    sudo chown $(id -u):$(id -g) $HOME/.kube/config
    KubeCtl.Taint    ${connection}    nodes --all node-role.kubernetes.io/master-
    Apply_Contive_Vpp_Plugin    ${connection}    ${normal_tag}    ${vpp_tag}
    # Verify k8s and plugin are running
    BuiltIn.Wait_Until_Keyword_Succeeds    240s    10s    Verify_K8s_With_Plugin_Running    ${connection}
    # join other nodes
    ${join_cmd} =    kube_parser.get_join_from_kubeadm_init    ${init_stdout}
    :FOR    ${index}    IN RANGE    2    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    ${connection} =    BuiltIn.Set_Variable    ${VM_SSH_ALIAS_PREFIX}${index}
    \    SshCommons.Switch_And_Execute_Command    ${connection}    sudo ${join_cmd}    ignore_stderr=${True}
    Wait_Until_Cluster_Ready    ${VM_SSH_ALIAS_PREFIX}1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}
    # label the nodes
    :FOR    ${index}    IN RANGE    1    ${KUBE_CLUSTER_${CLUSTER_ID}_NODES}+1
    \    KubeCtl.Label_Nodes    ${VM_SSH_ALIAS_PREFIX}1    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_HOST_NAME}   location    ${KUBE_CLUSTER_${CLUSTER_ID}_VM_${index}_LABEL}
    BuiltIn.Set_Suite_Variable    ${testbed_connection}    ${VM_SSH_ALIAS_PREFIX}1

Get_Docker_Tags
    [Documentation]    Depending on variables set, construct and return two docker tags to use.
    ${default} =    BuiltIn.Set_Variable_If    """${BRANCH}""" == "dev"    dev    latest
    # TODO: Contribute to BuiltIn so that Return_From_Keyword_Unless exists.
    BuiltIn.Return_From_Keyword_If    not """${TAG}"""    ${default}    ${default}
    ${normal_tag} =    Builtin.Set_Variable_If    """${BRANCH}""" == "master"    ${TAG}    ${BRANCH}-${TAG}
    Builtin.Log    ${normal_tag}
    ${vpp_tag} =    BuiltIn.Set_Variable    ${TAG}-${VPP}
    Builtin.Log    ${vpp_tag}
    [Return]    ${normal_tag}    ${vpp_tag}

Uninstall_Cri
    [Documentation]    Download and execute script with uninstall flag on active connection.
    SshCommons.Execute_Command_And_Log    curl -s ${CRI_INSTALL_URL} | sudo bash /dev/stdin -u    ignore_stderr=${True}    ignore_rc=${True}

Install_Cri
    [Arguments]    ${normal_tag}
    [Documentation]    Download, edit and execute script on active connection.
    BuiltIn.Log_Many    ${normal_tag}
    ${file_path} =    BuiltIn.Set_Variable    ${RESULTS_FOLDER}/cri-install.sh
    # TODO: Add error checking for OperatingSystem calls.
    OperatingSystem.Run    curl -s ${CRI_INSTALL_URL} > ${file_path}
    OperatingSystem.Run    sed -i 's@contivvpp/cri@contivvpp/cri:${normal_tag}@g' ${file_path}
    SshCommons.Execute_Command_With_Copied_File    ${file_path}    sudo bash    ignore_stderr=${True}

Docker_Pull_Contiv_Vpp
    [Arguments]    ${ssh_session}
    [Documentation]    Execute bash applying pull-images.sh from github.
    BuiltIn.Log_Many    ${ssh_session}
    SshCommons.Switch_And_Execute_Command    ${ssh_session}    bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/${BRANCH}/k8s/pull-images.sh)

Docker_Pull_Custom_Kube_Proxy
    [Arguments]    ${ssh_session}
    [Documentation]    Execute proxy-install.sh script.
    Builtin.Log_Many    ${ssh_session}
    SshCommons.Switch_And_Execute_Command    ${ssh_session}    bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/${BRANCH}/k8s/proxy-install.sh)

Apply_Contive_Vpp_Plugin
    [Arguments]    ${ssh_session}    ${normal_tag}    ${vpp_tag}
    [Documentation]    Apply file from URL ${NV_PLUGIN_URL} after editing in specific docker tags.
    BuiltIn.Log_Many    ${ssh_session}    ${normal_tag}    ${vpp_tag}
    SSHLibrary.Switch_Connection    ${ssh_session}
    ${file_path} =    BuiltIn.Set_Variable    ${RESULTS_FOLDER}/contiv-vpp.yaml
    # TODO: Add error checking for OperatingSystem calls.
    OperatingSystem.Run    curl -s ${NV_PLUGIN_URL} > ${file_path}
    OperatingSystem.Run    sed -i 's@image: contivvpp/cni@image: contivvpp/cni:${normal_tag}@g' ${file_path}
    OperatingSystem.Run    sed -i 's@image: contivvpp/ksr@image: contivvpp/ksr:${normal_tag}@g' ${file_path}
    OperatingSystem.Run    sed -i 's@image: contivvpp/vswitch@image: contivvpp/vswitch:${vpp_tag}@g' ${file_path}
    KubeCtl.Apply_F    ${ssh_session}    ${file_path}

Verify_All_Pods_Running
    [Arguments]    ${ssh_session}    ${excluded_pod_prefix}=invalid-pod-prefix-
    [Documentation]     Iterate over all pods of all namespaces (skipping \${excluded_pod_prefix} matches) and check running state.
    BuiltIn.Log_Many    ${ssh_session}    ${excluded_pod_prefix}
    ${all_pods_dict} =    KubeCtl.Get_Pods_All_Namespaces    ${ssh_session}
    ${pod_names} =    Collections.Get_Dictionary_Keys    ${all_pods_dict}
    : FOR    ${pod_name}   IN    @{pod_names}
    \     BuiltIn.Continue_For_Loop_If    """${excluded_pod_prefix}""" in """${pod_name}"""
    \     ${namesp} =    BuiltIn.Evaluate    &{all_pods_dict}[${pod_name}]['NAMESPACE']
    \     Verify_Pod_Running_And_Ready    ${ssh_session}    ${pod_name}    namespace=${namesp}

Verify_K8s_With_Plugin_Running
    [Arguments]    ${ssh_session}
    [Documentation]     We check for a particular (hardcoded) number of pods after init. Might be later replaced with
    ...    more detailed asserts.
    BuiltIn.Log_Many    ${ssh_session}
    BuiltIn.Comment    TODO: Make the expected number of pods configurable.
    ${all_pods_dict} =    KubeCtl.Get_Pods_All_Namespaces    ${ssh_session}
    BuiltIn.Length_Should_Be   ${all_pods_dict}     9
    Verify_All_Pods_Running    ${ssh_session}

Get_Pod_Name_List_By_Prefix
    [Arguments]    ${ssh_session}    ${pod_prefix}
    [Documentation]    Get pods from all namespaces, parse with specified \${pod_prefix}, log and return the parsed result.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_prefix}
    BuiltIn.Comment    TODO: Unify with Get_Pods or Get_Pods_All_Namespaces in KubeCtl.
    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${ssh_session}    kubectl get pods --all-namespaces
    ${output} =    kube_parser.parse_kubectl_get_pods_and_get_pod_name    ${stdout}    ${pod_prefix}
    Builtin.Log    ${output}
    [Return]    ${output}

Deploy_Client_And_Server_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}    ${server_file}=${SERVER_POD_FILE}
    [Documentation]     Deploy and verify client and server ubuntu pods and store their names.
    BuiltIn.Log_Many    ${ssh_session}    ${client_file}    ${server_file}
    ${client_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${client_file}    ubuntu-client-
    ${server_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${server_file}    ubuntu-server-
    BuiltIn.Set_Suite_Variable    ${client_pod_name}
    BuiltIn.Set_Suite_Variable    ${server_pod_name}

Deploy_Client_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}
    [Documentation]     Deploy client ubuntu pod. Pod name in the yaml file is expected to be ubuntu-client.
    BuiltIn.Log_Many    ${ssh_session}    ${client_file}
    ${client_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${client_file}    ubuntu-client-
    BuiltIn.Set_Suite_Variable    ${client_pod_name}

Deploy_Server_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${server_file}=${SERVER_POD_FILE}    ${timeout}=60s
    [Documentation]     Deploy server ubuntu pod. Pod name in the yaml file is expected to be ubuntu-server.
    BuiltIn.Log_Many    ${ssh_session}    ${server_file}    ${timeout}
    ${server_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${server_file}    ubuntu-server-    timeout=${timeout}
    BuiltIn.Set_Suite_Variable    ${server_pod_name}

Remove_Client_And_Server_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}    ${server_file}=${SERVER_POD_FILE}
    [Documentation]    Execute delete commands, wait until both pods are removed.
    BuiltIn.Log_Many    ${ssh_session}    ${client_file}    ${server_file}
    KubeCtl.Delete_F    ${ssh_session}    ${client_file}
    KubeCtl.Delete_F    ${ssh_session}    ${server_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${client_pod_name}
    Wait_Until_Pod_Removed    ${ssh_session}    ${server_pod_name}

Remove_Client_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}
    [Documentation]    Execute delete command, wait until pod is removed.
    BuiltIn.Log_Many    ${ssh_session}    ${client_file}
    KubeCtl.Delete_F    ${ssh_session}    ${client_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${client_pod_name}

Remove_Server_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${server_file}=${SERVER_POD_FILE}
    KubeCtl.Delete_F    ${ssh_session}    ${server_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${server_pod_name}

Deploy_Client_And_Nginx_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}    ${nginx_file}=${NGINX_POD_FILE}
    [Documentation]     Deploy and verify one ubuntu client (from \${client_file}) and one nginx pod (from \${nginx_file}), store their names.
    BuiltIn.Log_Many    ${ssh_session}    ${client_file}    ${nginx_file}
    ${client_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${client_file}    ubuntu-client-
    ${nginx_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${nginx_file}    nginx-
    BuiltIn.Set_Suite_Variable    ${client_pod_name}
    BuiltIn.Set_Suite_Variable    ${nginx_pod_name}

Deploy_Nginx_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${nginx_file}=${NGINX_POD_FILE}
    [Documentation]     Deploy one nginx pod
    BuiltIn.Log_Many    ${ssh_session}    ${nginx_file}
    ${nginx_pod_name} =    Deploy_Pod_And_Verify_Running    ${ssh_session}    ${nginx_file}    nginx-
    BuiltIn.Set_Suite_Variable    ${nginx_pod_name}

Verify_Multireplica_Pods_Running
    [Arguments]    ${ssh_session}    ${pod_prefix}    ${nr_replicas}    ${namespace}
    [Documentation]     Check there is expected number of pods and they are running.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_prefix}    ${nr_replicas}    ${namespace}
    BuiltIn.Comment    TODO: Join single- and multi- replica keywords.
    ${pods_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    ${pod_prefix}
    BuiltIn.Length_Should_Be   ${pods_list}     ${nr_replicas}
    : FOR    ${pod_name}    IN    @{pods_list}
    \    Verify_Pod_Running_And_Ready    ${ssh_session}    ${pod_name}    namespace= ${namespace}
    BuiltIn.Return_From_Keyword    ${pods_list}

Deploy_Multireplica_Pods_And_Verify_Running
    [Arguments]    ${ssh_session}    ${pod_file}    ${pod_prefix}    ${nr_replicas}    ${namespace}=default    ${setup_timeout}=60s
    [Documentation]     Apply the provided yaml file with more replica specified, wait until pods are running, return pods details.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_file}    ${pod_prefix}    ${nr_replicas}    ${namespace}    ${setup_timeout}
    BuiltIn.Comment    TODO: Join single- and multi- replica keywords.
    KubeCtl.Apply_F    ${ssh_session}    ${pod_file}
    ${pods_details} =    BuiltIn.Wait_Until_Keyword_Succeeds    ${setup_timeout}   4s    Verify_Multireplica_Pods_Running    ${ssh_session}    ${pod_prefix}    ${nr_replicas}    ${namespace}
    BuiltIn.Set_Suite_Variable    ${pods_details}

Verify_Multireplica_Pods_Removed
    [Arguments]    ${ssh_session}    ${pod_prefix}
    [Documentation]     Check no pods are running with prefix: ${pod_prefix}
    BuiltIn.Log_Many    ${ssh_session}    ${pod_prefix}
    BuiltIn.Comment    TODO: Join single- and multi- replica keywords.
    ${pods_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    ${pod_prefix}
    BuiltIn.Length_Should_Be   ${pods_list}     0

Remove_Multireplica_Pods_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${pod_file}    ${pod_prefix}
    [Documentation]     Remove pods and verify they are removed.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_file}    ${pod_prefix}
    KubeCtl.Delete_F    ${ssh_session}    ${pod_file}
    BuiltIn.Wait_Until_Keyword_Succeeds    60s    5s    Verify_Multireplica_Pods_Removed    ${ssh_session}    ${pod_prefix}

Remove_Client_And_Nginx_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${client_file}=${CLIENT_POD_FILE}    ${nginx_file}=${NGINX_POD_FILE}
    [Documentation]    Issue delete commands for pods defined by \${client_file} and \${nginx_file}, wait for the pods to get removed.
    BuiltIn.Log_Many    ${ssh_session}    ${client_file}    ${nginx_file}
    KubeCtl.Delete_F    ${ssh_session}    ${client_file}
    KubeCtl.Delete_F    ${ssh_session}    ${nginx_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${client_pod_name}
    Wait_Until_Pod_Removed    ${ssh_session}    ${nginx_pod_name}

Remove_Nginx_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${nginx_file}=${NGINX_POD_FILE}
    [Documentation]    Remove pod and verify removal, nginx being the default file.
    BuiltIn.Log_Many    ${ssh_session}    ${nginx_file}
    KubeCtl.Delete_F    ${ssh_session}    ${nginx_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${nginx_pod_name}

Verify_Istio_Running
    [Arguments]    ${ssh_session}
    [Documentation]    Get list of istio pod namess, check ther number maches the hardcoded value, verify each pod is running and ready, log and return the list.
    BuiltIn.Log_Many    ${ssh_session}
    ${istio_pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    istio
    BuiltIn.Length_Should_Be   ${istio_pod_list}     5
    : FOR    ${istio_pod_name}    IN    @{istio_pod_list}
    \    Verify_Pod_Running_And_Ready    ${ssh_session}    ${istio_pod_name}    namespace=istio-system
    Builtin.Log    ${istio_pod_list}
    [Return]    ${istio_pod_list}

Deploy_Istio_And_Verify_Running
    [Arguments]    ${ssh_session}
    [Documentation]     Deploy pod defined by ${ISTIO_FILE}, wait to see it running, store istio pod list.
    BuiltIn.Log_Many    ${ssh_session}
    KubeCtl.Apply_F    ${ssh_session}    ${ISTIO_FILE}
    ${istio_pods} =    BuiltIn.Wait_Until_Keyword_Succeeds    60s    4s    Verify_Istio_Running    ${ssh_session}
    BuiltIn.Set_Suite_Variable    ${istio_pods}

Verify_Istio_Removed
    [Arguments]    ${ssh_session}
    [Documentation]     Get list of defined istio pods, check it is empty.
    BuiltIn.Log_Many    ${ssh_session}
    ${istio_pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    istio
    BuiltIn.Length_Should_Be   ${istio_pod_list}     0

Remove_Istio_And_Verify_Removed
    [Arguments]    ${ssh_session}
    [Documentation]     Remove pod defined by ${ISTIO_FILE} expecring rc=1, verify no istio pod remains.
    BuiltIn.Log_Many    ${ssh_session}
    KubeCtl.Delete_F    ${ssh_session}    ${ISTIO_FILE}    expected_rc=${1}    ignore_stderr=${True}
    BuiltIn.Wait_Until_Keyword_Succeeds    60s    5s    Verify_Istio_Removed    ${ssh_session}

Get_Deployed_Pod_Name
    [Arguments]    ${ssh_session}    ${pod_prefix}
    [Documentation]    Get list of pod names matching the prefix, check tere is just one, return the name.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_prefix}
    ${pod_name_list} =   Get_Pod_Name_List_By_Prefix    ${ssh_session}    ${pod_prefix}
    BuiltIn.Length_Should_Be    ${pod_name_list}    1
    ${pod_name} =    BuiltIn.Evaluate     ${pod_name_list}[0]
    [Return]    ${pod_name}

Deploy_Pod_And_Verify_Running
    [Arguments]    ${ssh_session}    ${pod_file}    ${pod_prefix}    ${timeout}=60s
    [Documentation]    Deploy pod defined by \${pod_file}, wait until a pod matching \${pod_prefix} appears, check it was only 1 such pod, extract its name, wait until it is running, log and return the name.
    Builtin.Log_Many    ${ssh_session}    ${pod_file}    ${pod_prefix}
    KubeCtl.Apply_F    ${ssh_session}    ${pod_file}
    ${pod_name} =    BuiltIn.Wait_Until_Keyword_Succeeds    10s    2s    Get_Deployed_Pod_Name    ${ssh_session}    ${pod_prefix}
    Wait_Until_Pod_Running    ${ssh_session}    ${pod_name}    timeout=${timeout}
    BuiltIn.Log    ${pod_name}
    [Return]    ${pod_name}

Remove_Pod_And_Verify_Removed
    [Arguments]    ${ssh_session}    ${pod_file}    ${pod_name}
    [Documentation]    Remove pod defined by \${pod_file}, wait for \${pod_name} to get removed.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_file}    ${pod_name}
    KubeCtl.Delete_F    ${ssh_session}    ${pod_file}
    Wait_Until_Pod_Removed    ${ssh_session}    ${pod_name}

Verify_Pod_Running_And_Ready
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    [Documentation]    Get pods of \${namespace}, parse status of \${pod_name}, check it is Running, parse for ready containes of \${pod_name}, check it is all of them.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_name}    ${namespace}
    &{pods} =     KubeCtl.Get_Pods    ${ssh_session}    namespace=${namespace}
    ${status} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['STATUS']
    BuiltIn.Should_Be_Equal_As_Strings    ${status}    Running
    ${ready} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['READY']
    ${ready_containers}    ${out_of_containers} =    String.Split_String    ${ready}    separator=${/}    max_split=1
    BuiltIn.Should_Be_Equal_As_Strings    ${ready_containers}    ${out_of_containers}

Wait_Until_Pod_Running
    [Arguments]    ${ssh_session}    ${pod_name}    ${timeout}=60s    ${check_period}=5s    ${namespace}=default
    [Documentation]    WUKS around Verify_Pod_Running_And_Ready.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_name}    ${timeout}    ${check_period}    ${namespace}
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Running_And_Ready    ${ssh_session}    ${pod_name}    namespace=${namespace}

Verify_Pod_Not_Present
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    [Documentation]    Get pods for \${namespace}, check \${pod_name} is not one of them.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_name}    ${namespace}
    ${pods} =     KubeCtl.Get_Pods    ${ssh_session}    namespace=${namespace}
    Collections.Dictionary_Should_Not_Contain_Key     ${pods}    ${pod_name}

Wait_Until_Pod_Removed
    [Arguments]    ${ssh_session}    ${pod_name}    ${timeout}=120s    ${check_period}=5s    ${namespace}=default
    [Documentation]    WUKS around Verify_Pod_Not_Present.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_name}    ${timeout}    ${check_period}    ${namespace}
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Not_Present    ${ssh_session}    ${pod_name}    namespace=${namespace}

Run_Finite_Command_In_Pod
    [Arguments]    ${command}    ${ssh_session}=${EMPTY}    ${prompt}=${EMPTY}
    [Documentation]    Switch if \${ssh_session}, configure if \${prompt}, write \${command}, read until prompt, log and return text output.
    BuiltIn.Log_Many    ${command}     ${ssh_session}     ${prompt}
    BuiltIn.Comment    TODO: Do not mention pods and move to SshCommons.robot or similar.
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    ${command}
    ${output} =     SSHLibrary.Read_Until_Prompt
    SshCommons.Append_Command_Log    ${command}    ${output}
    [Return]    ${output}

Init_Infinite_Command_In_Pod
    [Arguments]    ${command}    ${ssh_session}=${EMPTY}    ${prompt}=${EMPTY}
    [Documentation]    Switch if \${ssh_session}, configure if \${prompt}, write \${command}.
    BuiltIn.Log_Many    ${command}    ${ssh_session}    ${prompt}
    BuiltIn.Comment    TODO: Do not mention pods and move to SshCommons.robot or similar.
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    SSHLibrary.Write    ${command}
    SshCommons.Append_Command_Log    ${command}

Stop_Infinite_Command_In_Pod
    [Arguments]    ${ssh_session}=${EMPTY}     ${prompt}=${EMPTY}
    [Documentation]    Switch if \${ssh_session}, configure if \${prompt}, write ctrl+c, read until prompt, log and return output.
    BuiltIn.Log_Many    ${ssh_session}    ${prompt}
    BuiltIn.Comment    TODO: Do not mention pods and move to SshCommons.robot or similar.
    BuiltIn.Run_Keyword_If    """${ssh_session}""" != """${EMPTY}"""     SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    Write_Bare_Ctrl_C
    ${output1} =     SSHLibrary.Read_Until    ^C
    ${output2} =     SSHLibrary.Read_Until_Prompt
    BuiltIn.Log_Many     ${output1}    ${output2}
    ${output} =    Builtin.Set_Variable    ${output1}${output2}
    SshCommons.Append_Command_Log    ^C    ${output}
    [Return]    ${output}

Write_Bare_Ctrl_C
    [Documentation]    Construct ctrl+c character and SSH-write it (without endline) to the current SSH connection.
    ...    Do not read anything yet.
    BuiltIn.Comment    TODO: Move to SshCommons.robot or similar.
    ${ctrl_c} =    BuiltIn.Evaluate    chr(int(3))
    SSHLibrary.Write_Bare    ${ctrl_c}

Get_Into_Container_Prompt_In_Pod
    [Arguments]    ${ssh_session}    ${pod_name}    ${prompt}=${EMPTY}
    [Documentation]    Configure if prompt, execute interactive bash in ${pod_name}, read until prompt, log and return output.
    BuiltIn.Log_Many    ${ssh_session}    ${pod_name}    ${prompt}
    # TODO: PodBash.robot?
    ${docker} =    BuiltIn.Set_Variable    ${KUBE_CLUSTER_${CLUSTER_ID}_DOCKER_COMMAND}
    ${container_id} =    KubeCtl.Get_Container_Id    ${ssh_session}    ${pod_name}
    # That already switched the ssh session.
    BuiltIn.Run_Keyword_If    """${prompt}""" != """${EMPTY}"""    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    ${command} =    BuiltIn.Set_Variable    ${docker} exec -i -t --privileged=true ${container_id} /bin/bash
    SSHLibrary.Write    ${command}
    ${output} =     SSHLibrary.Read_Until_Prompt
    SshCommons.Append_Command_Log    ${command}    ${output}
    [Return]    ${output}

Leave_Container_Prompt_In_Pod
    [Arguments]     ${ssh_session}    ${prompt}=$
    [Documentation]    Configure prompt, send ctrl+c, write "exit", read until prompt, log and return output.
    BuiltIn.Log_Many    ${ssh_session}    ${prompt}
    # TODO: PodBash.robot?
    SSHLibrary.Switch_Connection    ${ssh_session}
    SSHLibrary.Set_Client_Configuration    prompt=${prompt}
    Write_Bare_Ctrl_C
    SSHLibrary.Write    exit
    ${output} =     SSHLibrary.Read_Until_Prompt
    SshCommons.Append_Command_Log    ^Cexit    ${output}
    [Return]    ${output}

Verify_Cluster_Node_Ready
    [Arguments]    ${ssh_session}    ${node_name}
    [Documentation]    Get nodes, parse status of \${node_name}, check it is Ready, return nodes.
    BuiltIn.Log_Many    ${ssh_session}    ${node_name}
    BuiltIn.Comment    FIXME: Avoid repeated get_nodes when called from Verify_Cluster_Ready.
    ${nodes} =    KubeCtl.Get_Nodes    ${ssh_session}
    ${status} =    BuiltIn.Evaluate    &{nodes}[${node_name}]['STATUS']
    BuiltIn.Should_Be_Equal    ${status}    Ready
    [Return]    ${nodes}

Verify_Cluster_Ready
    [Arguments]     ${ssh_session}    ${nr_nodes}
    [Documentation]    Get nodes, check there are \${nr_nodes}, for each node Verify_Cluster_Node_Ready.
    BuiltIn.Log_Many     ${ssh_session}    ${nr_nodes}
    ${nodes} =    KubeCtl.Get_Nodes    ${ssh_session}
    BuiltIn.Length_Should_Be    ${nodes}    ${nr_nodes}
    ${names} =     Collections.Get_Dictionary_Keys     ${nodes}
    : FOR    ${name}    IN    @{names}
    \    Verify_Cluster_Node_Ready    ${ssh_session}    ${name}

Wait_Until_Cluster_Ready
    [Arguments]    ${ssh_session}    ${nr_nodes}    ${timeout}=180s    ${check_period}=5s
    [Documentation]    WUKS around Verify_Cluster_Ready.
    BuiltIn.Log_Many    ${ssh_session}    ${nr_nodes}    ${timeout}    ${check_period}
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Cluster_Ready    ${ssh_session}    ${nr_nodes}

Log_Contiv_Etcd
    [Arguments]    ${ssh_session}
    [Documentation]    Check there is exactly one etcd pod, get its logs
    ...    (and do nothing with them, except the implicit Log).
    Builtin.Log_Many    ${ssh_session}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    contiv-etcd-
    BuiltIn.Length_Should_Be    ${pod_list}    1
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system

Log_Contiv_Ksr
    [Arguments]    ${ssh_session}
    [Documentation]    Check there is exactly one ksr pod, get its logs
    ...    (and do nothing with them, except the implicit Log).
    Builtin.Log_Many    ${ssh_session}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    contiv-ksr-
    BuiltIn.Length_Should_Be    ${pod_list}    1
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system

Log_Contiv_Vswitch
    [Arguments]    ${ssh_session}    ${exp_nr_vswitch}=${KUBE_CLUSTER_${CLUSTER_ID}_NODES}
    [Documentation]    Check there is expected number of vswitch pods, get logs from them an cni containers
    ...    (and do nothing except the implicit Log).
    Builtin.Log_Many    ${ssh_session}    ${exp_nr_vswitch}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    contiv-vswitch-
    BuiltIn.Length_Should_Be    ${pod_list}    ${exp_nr_vswitch}
    : FOR    ${vswitch_pod}    IN    @{pod_list}
    \    KubeCtl.Logs    ${ssh_session}    ${vswitch_pod}    namespace=kube-system    container=contiv-cni
    \    KubeCtl.Logs    ${ssh_session}    ${vswitch_pod}    namespace=kube-system    container=contiv-vswitch

Log_Kube_Dns
    [Arguments]    ${ssh_session}
    [Documentation]    Check there is exactly one dns pod, get logs from kubedns, dnsmasq and sidecar containers
    ...    (and do nothing with them, except the implicit Log).
    Builtin.Log_Many    ${ssh_session}
    ${pod_list} =    Get_Pod_Name_List_By_Prefix    ${ssh_session}    kube-dns-
    BuiltIn.Length_Should_Be    ${pod_list}    1
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=kubedns
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=dnsmasq
    KubeCtl.Logs    ${ssh_session}    @{pod_list}[0]    namespace=kube-system    container=sidecar

Log_Pods_For_Debug
    [Arguments]    ${ssh_session}    ${exp_nr_vswitch}=${KUBE_CLUSTER_${CLUSTER_ID}_NODES}
    [Documentation]    Call multiple keywords to get various logs
    ...    (and do nothing with them, except the implicit Log).
    Builtin.Log_Many    ${ssh_session}    ${exp_nr_vswitch}
    Log_Contiv_Etcd    ${ssh_session}
    Log_Contiv_Ksr    ${ssh_session}
    Log_Contiv_Vswitch    ${ssh_session}    ${exp_nr_vswitch}
    Log_Kube_Dns    ${ssh_session}
