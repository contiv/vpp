*** Settings ***
Documentation     Basic test suite to verify "host to pod" and "pod to pod" communication.
Suite Setup       SSetup
Suite Teardown    STeardown
Resource          ${CURDIR}/../libraries/KubeCtlViaVagrantShell.robot
Resource          ${CURDIR}/../libraries/VagrantShell.robot
Resource          ${CURDIR}/../variables/Defaults.robot
Resource          ${CURDIR}/../libraries/KubernetesEnvViaVagrantShell.robot
Library           ${CURDIR}/../libraries/help_py_utils.py

*** Variables ***
${pod1_name}      alpine1
${pod2_name}      nginx1
${pod1_location}    ${K8S_TEST_NODE1}
${pod2_location}    ${K8S_TEST_NODE2}

*** Test Cases ***
Ping_Host_To_Pod_Different_Nodes
    [Documentation]    Ping from host(node1) to pod(node2).
    ${ro}=    VagrantShell.Vagrant_Ssh_With_Command    ping -${pod2_ip_version} -c 5 ${pod2_ip}
    BuiltIn.Should_Contain_Any    ${ro.stdout}    5 received, 0% packet loss    4 received, 20% packet loss

Curl_Host_To_Pod_Different_Nodes
    [Documentation]    Tcp traffic between host(node1) and pod(node2).
    ${ro}=    VagrantShell.Vagrant_Ssh_With_Command    curl [${pod2_ip}]
    BuiltIn.Should_Contain    ${ro.stdout}    Welcome to nginx

Ping_Pod_To_Pod_Different_Nodes
    [Documentation]    Ping from pod(node1) to pod(node2).
    ${ro}=    KubeCtlViaVagrantShell.Exec    ${pod1_name}    ping -${pod2_ip_version} -c 5 ${pod2_ip}
    BuiltIn.Should_Contain    ${ro.stdout}    5 packets received, 0% packet loss

Curl_Pod_To_Pod_Different_Nodes
    [Documentation]    Tcp traffic between pod(node1) and pod(node2).
    BuiltIn.Pass_Execution_If    """${pod1_ip_version}"""=="""6"""    Curl is not installed due to ${pod1_name}'s ipv6 address. Alpine(apk) does not support it yet. Test SKIPPED.
    ${ro}=    KubeCtlViaVagrantShell.Exec    ${pod1_name}    curl ${pod2_ip}
    BuiltIn.Should_Contain    ${ro.stdout}    Welcome to nginx

*** Keywords ***
SSetup
    [Documentation]    Suite setup
    ...    Two pods (linux and nginx) are created. If linux pod has ipv4 address, curl is installed to test tcp traffic. Alpine linux has some problems if ipv6 address only is available.
    KubernetesEnvViaVagrantShell.Verify_All_Pods_Running
    VagrantShell.Vagrant_Upload    pod_${pod1_name}.yaml
    KubernetesEnvViaVagrantShell.Deploy_Pod_And_Verify_Running    ${pod1_name}    pod_node_selector=${pod1_location}
    ${pod1_details} =    KubeCtlViaVagrantShell.Describe_Pod    ${pod1_name}
    ${pod1_ip} =    BuiltIn.Evaluate    &{pod1_details}[${pod1_name}]["IP"]
    ${pod1_ip_version} =    help_py_utils.get_ip_version    ${pod1_ip}
    BuiltIn.Set_Suite_Variable    ${pod1_ip}
    BuiltIn.Set_Suite_Variable    ${pod1_ip_version}
    BuiltIn.Run_Keyword_If    """${pod1_ip_version}"""=="""4"""    KubeCtlViaVagrantShell.Exec    ${pod1_name}    apk --no-cache add curl
    VagrantShell.Vagrant_Upload    pod_${pod2_name}.yaml
    KubernetesEnvViaVagrantShell.Deploy_Pod_And_Verify_Running    ${pod2_name}    pod_node_selector=${pod2_location}
    ${pod2_details} =    KubeCtlViaVagrantShell.Describe_Pod    ${pod2_name}
    ${pod2_ip} =    BuiltIn.Evaluate    &{pod2_details}[${pod2_name}]["IP"]
    ${pod2_ip_version} =    help_py_utils.get_ip_version    ${pod2_ip}
    BuiltIn.Set_Suite_Variable    ${pod2_ip}
    BuiltIn.Set_Suite_Variable    ${pod2_ip_version}

STeardown
    [Documentation]    Remove created pods
    KubernetesEnvViaVagrantShell.Remove_Pod_And_Verify_Removed    ${pod2_name}
    KubernetesEnvViaVagrantShell.Remove_Pod_And_Verify_Removed    ${pod1_name}
