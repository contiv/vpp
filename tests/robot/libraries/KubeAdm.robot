*** Settings ***
Documentation     This is a library to handle kubeadm commands on the remote machine, towards which
...    ssh connection is opened.
Library    SSHLibrary

*** Keywords ***
KubeAdm__Execute_Command_And_Log
    [Arguments]    ${ssh_session}    ${command}    ${expected_rc}=0    ${ignore_stderr}=${False}
    SSHLibrary.Switch_Connection    ${ssh_session}
    ${stdout}    ${stderr}    ${rc} =    SSHLibrary.Execute_Command    ${command}    return_stderr=True    return_rc=True
    BuiltIn.Log    ${stdout}
    BuiltIn.Log    ${stderr}
    BuiltIn.Log    ${rc}
    BuiltIn.Run_Keyword_Unless    ${ignore_stderr}    BuiltIn.Should_Be_Empty    ${stderr}
    BuiltIn.Should_Be_Equal_As_Numbers    ${rc}    ${expected_rc}
    BuiltIn.Return_From_Keyword    ${stdout}

Reset
    [Arguments]    ${ssh_session}
    ${stdout} =     KubeAdm__Execute_Command_And_Log    ${ssh_session}    sudo kubeadm reset
    BuiltIn.Return_From_Keyword    ${stdout}

Init
    [Arguments]    ${ssh_session}    ${arguments}=--token-ttl 0 --pod-network-cidr=172.20.0.0/16
    ${stdout} =     KubeAdm__Execute_Command_And_Log    ${ssh_session}    sudo -E kubeadm init ${arguments}    ignore_stderr=${True}
    BuiltIn.Return_From_Keyword    ${stdout}
