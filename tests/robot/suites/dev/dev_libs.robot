*** Settings ***
Resource     ../../variables/${VARIABLES}_variables.robot
Resource     ../../libraries/all_libs.robot

Suite Setup       Testsuite Setup
Suite Teardown    Testsuite Teardown

*** Variables ***
${VARIABLES}=          common
${ENV}=                common

*** Test Cases ***
Do ls on vm1
    Execute On Machine    vm_1    ls

Do ls on vm2
    Write To Machine    vm_2    ls

*** Keywords ***
TestSetup
    Make Datastore Snapshots    ${TEST_NAME}_test_setup

TestTeardown
    Make Datastore Snapshots    ${TEST_NAME}_test_teardown

