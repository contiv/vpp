*** Settings ***
Documentation     This is a library to handle kubeadm commands on the remote machine, towards which
...               ssh connection is opened.
Resource          ${CURDIR}/all_libs.robot

*** Keywords ***
Reset
    [Arguments]    ${ssh_session}
    [Documentation]    Execute "sudo kubeadm reset" on \${ssh_session}.
    BuiltIn.Log_Many    ${ssh_session}
    BuiltIn.Run_Keyword_And_Return    SshCommons.Switch_And_Execute_Command    ${ssh_session}    sudo kubeadm reset

Init
    [Arguments]    ${ssh_session}    ${arguments}=--token-ttl 0 --pod-network-cidr=172.20.0.0/16 --skip-preflight-checks
    [Documentation]    Execute "sudo -E kubeadm init" with configurabe arguments on \${ssh_session}.
    Builtin.Log_Many    ${ssh_session}    ${arguments}
    BuiltIn.Comment    TODO: Take cidr from a global variable for user to override when needed.
    BuiltIn.Run_Keyword_And_Return    SshCommons.Switch_And_Execute_Command    ${ssh_session}    sudo -E kubeadm init ${arguments}    ignore_stderr=${True}
