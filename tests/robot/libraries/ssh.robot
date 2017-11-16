[Documentation] Keywords for ssh sessions

*** Settings ***

*** Keywords ***
Open SSH Connection
    [Arguments]         ${name}    ${ip}    ${user}    ${pswd}
    Log Many            ${name}    ${ip}    ${user}    ${pswd}
    Open Connection     ${ip}      alias=${name}
    ${out}=             Run Keyword If      "${pswd}"!="rsa_id"   Login                              ${user}   ${pswd}
    ${out2}=            Run Keyword If      "${pswd}"=="rsa_id"   SSHLibrary.Login_With_Public_Key   ${user}   %{HOME}/.ssh/id_rsa   any
    Run Keyword If      """${out}"""!="None"    Append To File    ${RESULTS_FOLDER}/output_${name}.log    *** Command: Login${\n}${out}${\n}
    Run Keyword If      """${out2}"""!="None"    Append To File    ${RESULTS_FOLDER}/output_${name}.log    *** Command: Login${\n}${out2}${\n}

Execute On Machine     [Arguments]              ${machine}               ${command}               ${log}=true
                       [Documentation]          *Execute On Machine ${machine} ${command}*
                       ...                      Executing ${command} on connection with name ${machine}
                       ...                      Output log is added to machine output log
                       Log Many                 ${machine}               ${command}               ${log}
                       Switch Connection        ${machine}
                       ${out}   ${stderr}=      Execute Command          ${command}    return_stderr=True
                       Log Many                 ${out}                   ${stderr}
                       ${status}=               Run Keyword And Return Status    Should Be Empty    ${stderr}
                       Run Keyword If           ${status}==False         Log     One or more error occured during execution of a command ${command} on ${machine}    level=WARN
                       Run Keyword If           '${log}'=='true'         Append To File    ${RESULTS_FOLDER}/output_${machine}.log    *** Command: ${command}${\n}${out}${\n}*** Error: ${stderr}${\n}
                       [Return]                 ${out}

Write To Machine       [Arguments]              ${machine}               ${command}               ${delay}=${SSH_READ_DELAY}s
                       [Documentation]          *Write Machine ${machine} ${command}*
                       ...                      Writing ${command} to connection with name ${machine}
                       ...                      Output log is added to machine output log
                       Log Many                 ${machine}               ${command}               ${delay}
                       Switch Connection        ${machine}
                       Write                    ${command}
                       ${out}=                  Read                     delay=${delay}
                       Log                      ${out}
                       Append To File           ${RESULTS_FOLDER}/output_${machine}.log    *** Command: ${command}${\n}${out}${\n}
                       [Return]                 ${out}

