*** Settings ***
Resource          ${CURDIR}/../../libraries/setup-teardown.robot
Resource          ${CURDIR}/../../libraries/SshCommons.robot
Resource          ${CURDIR}/../../variables/${VARIABLES}_variables.robot
Suite Setup       setup-teardown.Testsuite_Setup
Suite Teardown    setup-teardown.Testsuite_Teardown

*** Variables ***
${VARIABLES}      common
${ENV}            common

*** Test Cases ***
Do_ls_on_vm1
    SshCommons.Switch_And_Execute_Command    vm_1    ls

Do_ls_on_vm2
    SshCommons.Switch_And_Execute_Command    vm_2    ls
