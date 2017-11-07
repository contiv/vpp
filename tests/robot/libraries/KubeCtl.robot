*** Settings ***
Documentation     This is a library to handle kubectl commands on the remote machine, towards which
...    ssh connection is opened.
Library    Collections
Library    SSHLibrary
Library    String
Library    ${CURDIR}/kube_parser.py

*** Keywords ***
KubeCtl__Execute_Command_And_Log
    [Arguments]    ${ssh_session}    ${command}    ${expected_rc}=0    ${ignore_stderr}=${False}
    SSHLibrary.Switch_Connection    ${ssh_session}
    ${stdout}    ${stderr}    ${rc} =    SSHLibrary.Execute_Command    ${command}    return_stderr=True    return_rc=True
    BuiltIn.Log    ${stdout}
    BuiltIn.Log    ${stderr}
    BuiltIn.Log    ${rc}
    BuiltIn.Run_Keyword_Unless    ${ignore_stderr}    BuiltIn.Should_Be_Empty    ${stderr}
    BuiltIn.Should_Be_Equal_As_Numbers    ${rc}    ${expected_rc}
    BuiltIn.Return_From_Keyword    ${stdout}

KubeCtl__Execute_Command_And_Log_With_File
    [Arguments]    ${ssh_session}    ${file_path}    ${command_prefix}    ${expected_rc}=0    ${ignore_stderr}=${False}
    SSHLibrary.Switch_Connection    ${ssh_session}
    SSHLibrary.Put_File    ${file_path}    .
    ${splitted_path} =    String.Split_String    ${file_path}    separator=${/}
    BuiltIn.Run_Keyword_And_Return    KubeCtl__Execute_Command_And_Log    ${ssh_session}    ${command_prefix} @{splitted_path}[-1]    expected_rc=${expected_rc}    ignore_stderr=${ignore_stderr}

Apply_F
    [Arguments]    ${ssh_session}    ${file_path}
    KubeCtl__Execute_Command_And_Log_With_File    ${ssh_session}    ${file_path}    kubectl apply -f

Apply_F_Url
    [Arguments]    ${ssh_session}    ${url}
    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl apply -f ${url}

Delete_F
    [Arguments]    ${ssh_session}    ${file_path}    ${expected_rc}=0    ${ignore_stderr}=${False}
    KubeCtl__Execute_Command_And_Log_With_File    ${ssh_session}    ${file_path}    kubectl delete -f    expected_rc=${expected_rc}    ignore_stderr=${ignore_stderr}

Delete_F_Url
    [Arguments]    ${ssh_session}    ${url}    ${expected_rc}=0    ${ignore_stderr}=${False}
    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl delete -f ${url}    expected_rc=${expected_rc}    ignore_stderr=${ignore_stderr}

Get_Pod
    [Arguments]    ${ssh_session}    ${pod_name}    ${namespace}=default
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pod -n ${namespace} ${pod_name}
    ${output} =     kube_parser.parse_kubectl_get_pods    ${stdout}
    BuiltIn.Return_From_Keyword    ${output}
   
Get_Pods
    [Arguments]    ${ssh_session}    ${namespace}=default 
    ${status}    ${message} =    BuiltIn.Run_Keyword_And_Ignore_Error    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods -n ${namespace}
    BuiltIn.Run_Keyword_If    """${status}""" == """FAIL""" and """No resources found""" not in """${message}"""    FAIL    msg=${message}
    ${output} =     kube_parser.parse_kubectl_get_pods    ${message}
    BuiltIn.Return_From_Keyword    ${output}

Get_Pods_Wide
    [Arguments]    ${ssh_session}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods -o wide
    ${output} =     kube_parser.parse_kubectl_get_pods    ${stdout}
    BuiltIn.Return_From_Keyword    ${output}

Get_Pods_All_Namespaces
    [Arguments]    ${ssh_session}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get pods --all-namespaces
    ${output} =     kube_parser.parse_kubectl_get_pods    ${stdout}
    BuiltIn.Return_From_Keyword    ${output}

Get_Nodes
    [Arguments]    ${ssh_session}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl get nodes
    ${output} =     kube_parser.parse_kubectl_get_nodes    ${stdout}
    BuiltIn.Return_From_Keyword    ${output}

Logs
    [Arguments]    ${ssh_session}    ${cmd_param}
    BuiltIn.Run_Keyword_And_Return    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl logs ${cmd_param}

Describe_Pod
    [Arguments]    ${ssh_session}    ${pod_name}
    ${output} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl describe pod ${pod_name}
    ${details} =    kube_parser.parse_kubectl_describe_pod    ${output}
    BuiltIn.Return_From_Keyword    ${details}

Taint
    [Arguments]    ${ssh_session}    ${cmd_parameters}
    ${stdout} =    KubeCtl__Execute_Command_And_Log    ${ssh_session}    kubectl taint ${cmd_parameters}
    BuiltIn.Return_From_Keyword    ${stdout}
