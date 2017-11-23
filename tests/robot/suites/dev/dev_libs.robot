*** Settings ***
Resource          ${CURDIR}/../../libraries/all_libs.robot
Suite Setup       setup-teardown.Testsuite_Setup
Suite Teardown    setup-teardown.Testsuite_Teardown

*** Test Cases ***
Do_ls_on_vm1
    SshCommons.Switch_And_Execute_Command    vm_1    ls

Do_ls_on_vm2
    SshCommons.Switch_And_Execute_Command    vm_2    ls
