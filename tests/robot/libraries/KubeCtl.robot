*** Settings ***
Documentation     This is a library to handle kubectl commands on the remote machine, towards which
...    ssh connection is opened.
Library    Collections
Library    SSHLibrary
Library    String
Library    ${CURDIR}/kubectl_parser.py

*** Keywords ***
KubeCtl__Execute_Command_And_Log
    [Arguments]    ${ssh_session}    ${command}    ${expected_rc}=0
    SSHLibrary.Switch_Connection    ${ssh_session}
    ${stdout}    ${stderr}    ${rc} =    SSHLibrary.Execute_Command    ${command}    return_stderr=True    return_rc=True
    BuiltIn.Log    ${stdout}
    BuiltIn.Log    ${stderr}
    BuiltIn.Log    ${rc}
    BuiltIn.Should_Be_Empty    ${stderr}
    BuiltIn.Should_Be_Equal_As_Numbers    ${rc}    ${expected_rc}
    BuiltIn.Return_From_Keyword    ${stdout}

KubeCtl__Execute_Command_And_Log_With_File
    [Arguments]    ${ssh_session}    ${file_path}    ${command_prefix}
    SSHLibrary.Switch_Connection    ${ssh_session}
    SSHLibrary.Put_File    ${file_path}    .
    ${splitted_path} =    String.Split_String    ${file_path}    separator=${/}
    BuiltIn.Run_Keyword_And_Return    KubeCtl__Execute_Command_And_Log    ${ssh_session}    ${command_prefix} @{splitted_path}[-1]

Apply_F
    [Arguments]    ${ssh_session}    ${file_path}
    KubeCtl__Execute_Command_And_Log_With_File    ${ssh_session}    ${file_path}    kubectl apply -f

Apply_F_Url
    [Arguments]    ${ssh_session}    ${url}
    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl apply -f ${url}

Delete_F
    [Arguments]    ${ssh_session}    ${file_path}
    KubeCtl__Execute_Command_And_Log_With_File    ${ssh_session}    ${file_path}    kubectl delete -f

Delete_F_Url
    [Arguments]    ${ssh_session}    ${url}
    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl delete -f ${url}

Get_Pod
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pod -n ${namespace} ${pod_name}
    ${output} =     kubectl_parser.parse_kubectl_get_pods    ${stdout}
    BuiltIn.Return_From_Keyword    ${output}
   
Get_Pods
    [Arguments]    ${ssh_session}    ${namespace}=default 
    ${status}    ${message} =    BuiltIn.Run_Keyword_And_Ignore_Error    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods -n ${namespace}
    BuiltIn.Run_Keyword_If    """${status}""" == """FAIL""" and """No resources found""" not in """${message}"""    FAIL    msg=${message}
    ${output} =     kubectl_parser.parse_kubectl_get_pods    ${message}
    BuiltIn.Return_From_Keyword    ${output}

Get_Pods_Wide
    [Arguments]    ${ssh_session}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods -o wide
    ${output} =     kubectl_parser.parse_kubectl_get_pods    ${stdout}
    BuiltIn.Return_From_Keyword    ${output}

Get_Pods_All_Namespaces
    [Arguments]    ${ssh_session}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods --all-namespaces
    ${output} =     kubectl_parser.parse_kubectl_get_pods    ${stdout}
    BuiltIn.Return_From_Keyword    ${output}

Logs
    [Arguments]    ${ssh_session}    ${cmd_param}
    BuiltIn.Run_Keyword_And_Return    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl logs ${cmd_param}

Describe_Pod
    [Arguments]    ${ssh_session}    ${pod_name}
    ${output} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl describe pod ${pod_name}
    ${details} =    kubectl_parser.parse_kubectl_describe_pod    ${output}
    BuiltIn.Return_From_Keyword    ${details}

Get_Pod_Name_By_Prefix
    [Arguments]    ${ssh_session}    ${pod_prefix}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods --all-namespaces
    ${output} =     kubectl_parser.parse_kubectl_get_pods_and_get_pod_name    ${stdout}    ${pod_prefix}
    BuiltIn.Return_From_Keyword    ${output}

Verify_Pod_Running_And_Ready
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    &{pods} =     Get_Pods    ${ssh_session}    namespace=${namespace}
    ${status} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['STATUS']
    BuiltIn.Should_Be_Equal_As_Strings    ${status}    Running
    ${ready} =    BuiltIn.Evaluate    &{pods}[${pod_name}]['READY']
    ${ready_containers}    ${out_of_containers} =    String.Split_String    ${ready}    separator=${/}    max_split=1
    BuiltIn.Should_Be_Equal_As_Strings    ${ready_containers}    ${out_of_containers}

Wait_Until_Pod_Started
    [Arguments]    ${ssh_session}    ${pod_name}    ${timeout}=30s    ${check_period}=5s    ${namespace}=default
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Running_And_Ready    ${ssh_session}    ${pod_name}    namespace=${namespace}

Verify_Pod_Not_Present
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    ${pods} =     Get_Pods    ${ssh_session}    namespace=${namespace}
    Collections.Dictionary_Should_Not_Contain_Key     ${pods}    ${pod_name}

Wait_Until_Pod_Removed
    [Arguments]    ${ssh_session}    ${pod_name}    ${timeout}=90s    ${check_period}=5s    ${namespace}=default
    BuiltIn.Wait_Until_Keyword_Succeeds    ${timeout}    ${check_period}    Verify_Pod_Not_Present    ${ssh_session}    ${pod_name}    namespace=${namespace}
