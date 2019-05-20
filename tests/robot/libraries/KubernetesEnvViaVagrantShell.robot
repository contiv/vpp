*** Settings ***
Documentation     Basic pod and node functionality.
Resource    ${CURDIR}/KubeCtlViaVagrantShell.robot
Resource    ${CURDIR}/../variables/Defaults.robot
Library     Collections

*** Keywords ***
#Verify_All_Pods_Running
#    [Arguments]    ${ssh_session}    ${excluded_pod_prefix}=invalid-pod-prefix-
#    [Documentation]     Iterate over all pods of all namespaces (skipping \${excluded_pod_prefix} matches) and check running state.
#    BuiltIn.Log_Many    ${ssh_session}    ${excluded_pod_prefix}
#    ${all_pods_dict} =    KubeCtl.Get_Pods_All_Namespaces    ${ssh_session}
#    ${pod_names} =    Collections.Get_Dictionary_Keys    ${all_pods_dict}
#    : FOR    ${pod_name}   IN    @{pod_names}
#    \     BuiltIn.Continue_For_Loop_If    """${excluded_pod_prefix}""" in """${pod_name}"""
#    \     ${namesp} =    BuiltIn.Evaluate    &{all_pods_dict}[${pod_name}]['NAMESPACE']
#    \     Verify_Pod_Running_And_Ready    ${ssh_session}    ${pod_name}    namespace=${namesp}

#Get_Pod_Name_List_By_Prefix
#    [Arguments]    ${ssh_session}    ${pod_prefix}
#    [Documentation]    Get pods from all namespaces, parse with specified \${pod_prefix}, log and return the parsed result.
#    BuiltIn.Log_Many    ${ssh_session}    ${pod_prefix}
#    BuiltIn.Comment    TODO: Unify with Get_Pods or Get_Pods_All_Namespaces in KubeCtl.
#    ${stdout} =    SshCommons.Switch_And_Execute_Command    ${ssh_session}    kubectl get pods --all-namespaces
#    ${output} =    kube_parser.parse_kubectl_get_pods_and_get_pod_name    ${stdout}    ${pod_prefix}
#    Builtin.Log    ${output}
#    [Return]    ${output}

Deploy_Pod_And_Verify_Running
    [Arguments]     ${pod_name}    ${pod_node_selector}=${K8S_TEST_NODE1}    ${execution_node}=${K8S_MASTER}    ${timeout}=${POD_DEPLOY_DEFAULT_TIMEOUT}
    [Documentation]    Create pod and wait until it reaches the state READY 'n/n' (e.g. 1/1) and STATUS 'Running'.
    Builtin.Log_Many    ${pod_name}    ${pod_node_selector}    ${execution_node}    ${timeout}
    KubeCtlViaVagrantShell.Create_Pod    ${pod_name}     pod_node_selector=${pod_node_selector}    execution_node=${execution_node}
    Wait_Until_Pod_Running    ${pod_name}    timeout=${timeout}

Remove_Pod_And_Verify_Removed
    [Arguments]    ${pod_name}    ${execution_node}=${K8S_MASTER}
    [Documentation]    Remove pod by name and wait until removed.
    BuiltIn.Log_Many    ${pod_name}    ${execution_node}
    KubeCtlViaVagrantShell.Delete_Pod    ${pod_name}    execution_node=${execution_node}
    Wait_Until_Pod_Removed    ${pod_name}

Verify_Pod_Running_And_Ready
    [Arguments]    ${pod_name}    ${namespace}=default
    [Documentation]    Get pods of \${namespace}, parse status of \${pod_name}, check it is Running, parse for ready containes of \${pod_name}, check it is all of them.
    BuiltIn.Log_Many    ${pod_name}    ${namespace}
    &{pods} =     KubeCtlViaVagrantShell.Get_Pods    namespace=${namespace}
    ${status} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['STATUS']
    BuiltIn.Should_Be_Equal_As_Strings    ${status}    Running
    ${ready} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['READY']
    ${ready_containers}    ${out_of_containers} =    String.Split_String    ${ready}    separator=${/}    max_split=1
    BuiltIn.Should_Be_Equal_As_Strings    ${ready_containers}    ${out_of_containers}

Wait_Until_Pod_Running
    [Arguments]    ${pod_name}    ${timeout}=${POD_RUNNING_DEFAULT_TIMEOUT}    ${check_period}=5s    ${namespace}=default
    [Documentation]    WUKS around Verify_Pod_Running_And_Ready.
    BuiltIn.Log_Many    ${pod_name}    ${timeout}    ${check_period}    ${namespace}
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Running_And_Ready    ${pod_name}    namespace=${namespace}

Verify_Pod_Not_Present
    [Arguments]    ${pod_name}    ${namespace}=default
    [Documentation]    Get pods for \${namespace}, check \${pod_name} is not one of them.
    BuiltIn.Log_Many    ${pod_name}    ${namespace}
    ${pods} =     KubeCtlViaVagrantShell.Get_Pods    namespace=${namespace}
    Collections.Dictionary_Should_Not_Contain_Key     ${pods}    ${pod_name}

Wait_Until_Pod_Removed
    [Arguments]    ${pod_name}    ${timeout}=${POD_REMOVE_DEFAULT_TIMEOUT}    ${check_period}=5s    ${namespace}=default
    [Documentation]    WUKS around Verify_Pod_Not_Present.
    BuiltIn.Log_Many    ${pod_name}    ${timeout}    ${check_period}    ${namespace}
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Not_Present    ${pod_name}    namespace=${namespace}

#Verify_Cluster_Node_Ready
#    [Arguments]    ${ssh_session}    ${node_name}
#    [Documentation]    Get nodes, parse status of \${node_name}, check it is Ready, return nodes.
#    BuiltIn.Log_Many    ${ssh_session}    ${node_name}
#    BuiltIn.Comment    FIXME: Avoid repeated get_nodes when called from Verify_Cluster_Ready.
#    ${nodes} =    KubeCtl.Get_Nodes    ${ssh_session}
#    BuiltIn.Log    ${nodes}
#    ${status} =    BuiltIn.Evaluate    &{nodes}[${node_name}]['STATUS']
#    BuiltIn.Should_Be_Equal    ${status}    Ready
#    [Return]    ${nodes}

#Verify_Cluster_Ready
#    [Arguments]     ${ssh_session}    ${nr_nodes}
#    [Documentation]    Get nodes, check there are \${nr_nodes}, for each node Verify_Cluster_Node_Ready.
#    BuiltIn.Log_Many     ${ssh_session}    ${nr_nodes}
#    ${nodes} =    KubeCtl.Get_Nodes    ${ssh_session}
#    BuiltIn.Log    ${nodes}
#    BuiltIn.Length_Should_Be    ${nodes}    ${nr_nodes}
#    ${names} =     Collections.Get_Dictionary_Keys     ${nodes}
#    : FOR    ${name}    IN    @{names}
#    \    Verify_Cluster_Node_Ready    ${ssh_session}    ${name}

#Wait_Until_Cluster_Ready
#    [Arguments]    ${ssh_session}    ${nr_nodes}    ${timeout}=${CLUSTER_READY_TIMEOUT}    ${check_period}=5s
#    [Documentation]    WUKS around Verify_Cluster_Ready.
#    BuiltIn.Log_Many    ${ssh_session}    ${nr_nodes}    ${timeout}    ${check_period}
#    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Cluster_Ready    ${ssh_session}    ${nr_nodes}
