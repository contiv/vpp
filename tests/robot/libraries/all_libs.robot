*** Settings ***
Documentation     Library which includes all other libs
...
...
...

Library       String
Library       RequestsLibrary
Library       SSHLibrary            timeout=60s
Library       OperatingSystem

Resource      setup-teardown.robot
Resource      ssh.robot
