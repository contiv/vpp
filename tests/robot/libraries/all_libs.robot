*** Settings ***
Documentation     Aggregate library for all suites to include.
...
...               It is easier to maintain suites if import section is just one line.
...               As the amount of libraries is small, there should be no downsides,
...               long as Library.Keyword call format is used.
Library           Collections
Library           OperatingSystem
Library           SSHLibrary
Library           String
# kube-parser should not be called directly.
Resource          ${CURDIR}/KubeAdm.robot
Resource          ${CURDIR}/KubeCtl.robot
Resource          ${CURDIR}/KubernetesEnv.robot
Resource          ${CURDIR}/SshCommons.robot
Resource          ${CURDIR}/setup-teardown.robot
