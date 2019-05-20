*** Settings ***
Documentation     This library performs 'vagrant' commands in shell on local machine.
Library          Process

*** Keywords ***
Vagrant_Command
    [Arguments]    ${subcommand}
    [Documentation]    Execute given subcommand
    BuiltIn.Log_Many    ${subcommand}
    ${ro}=    Run Process    vagrant ${subcommand}    shell=True    cwd=${CURDIR}/../../../vagrant
    BuiltIn.Return_From_Keyword    ${ro}

Vagrant_Ssh_With_Command
    [Arguments]    ${command}    ${vagrant_node}=${K8S_MASTER}     ${ignore_error}=${False}
    [Documentation]    Execute command on given vagrant pod
    BuiltIn.Log_Many    ${command}    ${vagrant_node}    ${ignore_error}
    ${ro}=    Vagrant_Command    ssh ${vagrant_node} -c "${command}"
    BuiltIn.Return_From_Keyword_If    ${ignore_error}    ${ro}
    BuiltIn.Should_Be_Equal_As_Integers    ${ro.rc}    0    Vagrant command failed. Ro: ${ro.__dict__}
    BuiltIn.Return_From_Keyword    ${ro}

Vagrant_Upload
    [Arguments]    ${file_name}    ${dst_k8s_node}=${K8S_MASTER}
    [Documentation]    ${file_name} must be located in vpp.git/tests/robot/resources directory
    ${ro}=    Vagrant_Command    upload ../tests/robot/resources/${file_name} ${dst_k8s_node}
    BuiltIn.Should_Be_Equal_As_Integers    ${ro.rc}    0    Vagrant upload command failed. Ro: ${ro.__dict__}
