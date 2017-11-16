*** Settings ***
Documentation     This is a library for simple improvements over SSHLibrary for other robot libraries to use.
Library           OperatingSystem
Library           String
Library           SSHLibrary

*** Keywords ***
Open_Ssh_Connection
    [Arguments]    ${name}    ${ip}    ${user}    ${pswd}
    [Documentation]    Create SSH connection to \{ip} aliased as \${name} and log in using \${user} and \${pswd} (or rsa).
    ...    Log to output file. The new connection is left active.
    BuiltIn.Log_Many    ${name}    ${ip}    ${user}    ${pswd}
    SSHLibrary.Open_Connection    ${ip}    alias=${name}
    ${out} =    BuiltIn.Run_Keyword_If    """${pswd}""" != "rsa_id"    SSHLibrary.Login    ${user}    ${pswd}
    ${out2} =    BuiltIn.Run_Keyword_If    """${pswd}""" == "rsa_id"    SSHLibrary.Login_With_Public_Key    ${user}    %{HOME}/.ssh/id_rsa    any
    BuiltIn.Run_Keyword_If    """${out}""" != "None"    OperatingSystem.Append_To_File    ${RESULTS_FOLDER}/output_${name}.log    *** Command: Login${\n}${out}${\n}
    BuiltIn.Run_Keyword_If    """${out2}""" != "None"    OperatingSystem.Append_To_File    ${RESULTS_FOLDER}/output_${name}.log    *** Command: Login${\n}${out2}${\n}

Switch_And_Execute_With_Copied_File
    [Arguments]    ${ssh_session}    ${file_path}    ${command_prefix}    ${expected_rc}=0    ${ignore_stderr}=${False}
    [Documentation]    Switch to \${ssh_session} and continue with Execute_Command_With_Copied_File.
    BuiltIn.Log_Many    ${ssh_session}    ${file_path}    ${command_prefix}    ${expected_rc}    ${ignore_stderr}
    SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_And_Return    Execute_Command_With_Copied_File    ${file_path}    ${command_prefix}    expected_rc=${expected_rc}    ignore_stderr=${ignore_stderr}

Execute_Command_With_Copied_File
    [Arguments]    ${file_path}    ${command_prefix}    ${expected_rc}=0    ${ignore_stderr}=${False}
    [Documentation]    Put file to current remote directory and execute command which takes computed file name as argument.
    BuiltIn.Log_Many    ${file_path}    ${command_prefix}    ${expected_rc}    ${ignore_stderr}
    Builtin.Comment    TODO: Do not pollute current remote directory. See https://github.com/contiv/vpp/issues/195
    SSHLibrary.Put_File    ${file_path}    .
    ${splitted_path} =    String.Split_String    ${file_path}    separator=${/}
    BuiltIn.Run_Keyword_And_Return    Execute_Command_And_Log    ${command_prefix} @{splitted_path}[-1]    expected_rc=${expected_rc}    ignore_stderr=${ignore_stderr}

Switch_Execute_And_Log_To_File
    [Arguments]    ${ssh_session}    ${command}    ${expected_rc}=0    ${ignore_stderr}=${False}    ${ignore_rc}=${False}    ${log_stdout}=${False}
    [Documentation]    Call Switch_And_Execute_Command (by default without logging stdout), put stdout into a file. Return stdout.
    ...    To distinguish separate invocations, suite name, test name, session alias
    ...    and full command are used to construct file name.
    BuiltIn.Log_Many    ${ssh_session}    ${command}    ${expected_rc}    ${ignore_stderr}    ${ignore_rc}    ${log_stdout}
    ${stdout} =    Switch_And_Execute_Command    ${ssh_session}    ${command}    expected_rc=${expected_rc}    ignore_stderr=${ignore_stderr}    ignore_rc=${ignore_rc}    log_stdout=${log_stdout}
    # TODO: Create a separate library for putting data into automatically named files?
    ${underlined_command} =    String.Replace_String    ${command}    ${SPACE}    _
    # We rely on the requested session being active now.
    ${connection} =    SSHLibrary.Get_Connection
    # In teardown, ${TEST_NAME} does not exist.
    ${testname} =    BuiltIn.Get_Variable_Value    ${TEST_NAME}    ${EMPTY}
    ${filename} =    BuiltIn.Set_Variable    ${testname}__${SUITE_NAME}__${connection.alias}__${underlined_command}.log
    BuiltIn.Log    ${filename}
    OperatingSystem.Create_File    ${RESULTS_FOLDER}${/}${filename}    ${stdout}
    [Return]    ${stdout}

Switch_And_Execute_Command
    [Arguments]    ${ssh_session}    ${command}    ${expected_rc}=0    ${ignore_stderr}=${False}    ${ignore_rc}=${False}    ${log_stdout}=${True}
    [Documentation]    Switch to \${ssh_session}, and continue with Execute_Command_And_Log.
    BuiltIn.Log_Many    ${ssh_session}    ${command}    ${expected_rc}    ${ignore_stderr}    ${ignore_rc}    ${log_stdout}
    SSHLibrary.Switch_Connection    ${ssh_session}
    BuiltIn.Run_Keyword_And_Return    Execute_Command_And_Log    ${command}    expected_rc=${expected_rc}    ignore_stderr=${ignore_stderr}    ignore_rc=${ignore_rc}    log_stdout=${log_stdout}

Execute_Command_And_Log
    [Arguments]    ${command}    ${expected_rc}=0    ${ignore_stderr}=${False}    ${ignore_rc}=${False}    ${log_stdout}=${True}
    [Documentation]    Execute \${command} on current SSH session, log results, maybe fail on nonempty stderr, check \${expected_rc}, return stdout.
    BuiltIn.Log_Many    ${command}    ${expected_rc}    ${ignore_stderr}    ${ignore_rc}    ${log_stdout}
    ${stdout}    ${stderr}    ${rc} =    SSHLibrary.Execute_Command    ${command}    return_stderr=True    return_rc=True
    BuiltIn.Run_Keyword_If    ${log_stdout}    BuiltIn.Log    ${stdout}
    BuiltIn.Log    ${stderr}
    BuiltIn.Log    ${rc}
    BuiltIn.Run_Keyword_Unless    ${ignore_stderr}    BuiltIn.Should_Be_Empty    ${stderr}
    BuiltIn.Run_Keyword_Unless    ${ignore_rc}    BuiltIn.Should_Be_Equal_As_Numbers    ${rc}    ${expected_rc}
    [Return]    ${stdout}
