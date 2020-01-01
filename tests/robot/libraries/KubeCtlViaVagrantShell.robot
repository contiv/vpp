*** Settings ***
Documentation     This is a library to handle kubectl commands on the remote machine via vagrant ssh command.
...
...               This library implements commands which would in shell look like (e.g.):
...               vagrant ssh k8s-master -c kubectl describe pod <pod-name>
Resource          ${CURDIR}/VagrantShell.robot
Resource          ${CURDIR}/../variables/Defaults.robot
Library           ${CURDIR}/kube_parser.py
Library           String

*** Keywords ***
Create_Pod
    [Arguments]    ${pod_name}    ${pod_node_selector}=${K8S_TEST_NODE1}    ${execution_node}=${K8S_MASTER}
    [Documentation]    Create pod from file. Pod file should be already located in home directory at ${execution_node}.
    BuiltIn.Log_Many    ${pod_name}    ${pod_node_selector}    ${execution_node}
    ${cmd}=    BuiltIn.Set_Variable    NODE_SELECTOR=${pod_node_selector} envsubst < pod_${pod_name}.yaml | kubectl create -f -
    ${ro}=    VagrantShell.Vagrant_Ssh_With_Command    ${cmd}    vagrant_node=${execution_node}
    BuiltIn.Return_From_Keyword    ${ro}

Delete_Pod
    [Arguments]    ${pod_name}    ${execution_node}=${K8S_MASTER}
    [Documentation]    Execute kubectl delete pod \${pod_name} command.
    BuiltIn.Log_Many    ${pod_name}    ${execution_node}
    ${ro}=    VagrantShell.Vagrant_Ssh_With_Command    kubectl delete pod ${pod_name}    vagrant_node=${execution_node}
    BuiltIn.Return_From_Keyword    ${ro}

Get_Pods
    [Arguments]    ${namespace}=default    ${execution_node}=${K8S_MASTER}
    [Documentation]    Execute "kubectl get pods -n" for given \${namespace} tolerating zero resources, parse, log and return the parsed output.
    BuiltIn.Log_Many    ${namespace}    ${execution_node}
    ${cmd}=    BuiltIn.SetVariable    kubectl get pods -n ${namespace}
    ${ro}=    VagrantShell.Vagrant_Ssh_With_Command    ${cmd}    vagrant_node=${execution_node}
    ${output} =    kube_parser.parse_kubectl_get_pods    ${ro.stdout}
    BuiltIn.Log    ${output}
    BuiltIn.Return_From_Keyword    ${output}

Describe_Pod
    [Arguments]    ${pod_name}    ${execution_node}=${K8S_MASTER}
    [Documentation]    Execute "kubectl describe pod" with given \${pod_name}, parse, log and return the parsed details.
    BuiltIn.Log_Many    ${pod_name}    ${execution_node}
    ${ro} =    VagrantShell.Vagrant_Ssh_With_Command    kubectl describe pod ${pod_name}    vagrant_node=${execution_node}
    ${details} =    kube_parser.parse_kubectl_describe_pod    ${ro.stdout}
    BuiltIn.Log    ${details}
    BuiltIn.Return_From_Keyword    ${details}

Exec
    [Arguments]    ${pod_name}    ${cmd}    ${execution_node}=${K8S_MASTER}
    [Documentation]    Execute "kubectl exec" with given \${pod_name}, parse, log and return the parsed details.
    BuiltIn.Log_Many    ${pod_name}    ${cmd}    ${execution_node}
    ${ro} =    VagrantShell.Vagrant_Ssh_With_Command    kubectl exec ${pod_name} -- ${cmd}    vagrant_node=${execution_node}
    BuiltIn.Return_From_Keyword    ${ro}

Get_Pods_All_Namespaces
    [Arguments]    ${execution_node}=${K8S_MASTER}
    [Documentation]    Execute "kubectl get pods --all-namespaces", parse, log and return the parsed outpt.
    Builtin.Log_Many    ${execution_node}
    ${ro} =    VagrantShell.Vagrant_Ssh_With_Command    kubectl get pods --all-namespaces    vagrant_node=${execution_node}
    ${output} =    kube_parser.parse_kubectl_get_pods    ${ro.stdout}
    BuiltIn.Log    ${output}
    BuiltIn.Return_From_Keyword    ${output}
