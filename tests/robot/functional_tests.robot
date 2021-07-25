*** Settings ***
Documentation  Simple functional tests for https_dns_proxy
Library        OperatingSystem
Library        Process
Library        Collections


*** Variables ***
${BINARY_PATH}  ${CURDIR}/../../https_dns_proxy
${PORT}  55353


*** Settings ***
Test Setup     Start Proxy
Test Teardown  Stop Proxy


*** Keywords ***
Start Proxy
  [Arguments]  @{args}
  @{default_args} =  Create List  -v  -v  -v  -4  -p  ${PORT}
  @{proces_args} =  Combine Lists  ${default_args}  ${args}
  ${proxy} =  Start Process  ${BINARY_PATH}  @{proces_args}
  # ...  stdout=${TEMPDIR}/https_dns_proxy_robot_test_stdout.txt
  ...  stderr=STDOUT  alias=proxy
  Set Test Variable  ${proxy}
  Set Test Variable  &{expected_logs}  loop destroyed=1  # last log line
  Set Test Variable  @{error_logs}  [F]  # any fatal error
  Sleep  0.5

Stop Proxy
  Send Signal To Process  SIGINT  ${proxy}
  ${result} =  Wait For Process  ${proxy}  timeout=15 secs
  Log  ${result.stdout}
  FOR  ${log}  ${times}  IN  &{expected_logs}
    Should Contain X Times  ${result.stdout}  ${log}  ${times}
  END
  FOR  ${log}  IN  @{error_logs}
    Run Keyword And Expect Error  not found
    ...  Should Contain  ${result.stdout}  ${log}  msg=not found  values=False
  END
  Should Be Equal As Integers  ${result.rc}  0


Start Dig
  [Arguments]  ${domain}=google.com
  ${handle} =  Start Process  dig  +timeout\=2  +retry\=0  @127.0.0.1  -p  ${PORT}  ${domain}
  ...  stderr=STDOUT  alias=dig
  [Return]  ${handle}

Stop Dig
  [Arguments]  ${handle}
  ${result} =  Wait For Process  ${handle}  timeout=10 secs
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  ANSWER SECTION

Run Dig
  [Arguments]  ${domain}=google.com
  ${handle} =  Start Dig  ${domain}
  Stop Dig  ${handle}


*** Test Cases ***
Simple smoke test
  Run Dig

Handle Unbound Server Does Not Support HTTP/1.1
  [Setup]  NONE
  Start Proxy  -x  -r  https://doh.mullvad.net/dns-query  # resolver uses Unbound
  Run Keyword And Expect Error  9 != 0  # timeout exit code
  ...  Run Dig

Reuse HTTP/2 Connection
  [Documentation]  After first successful request, further requests should not open new connections
  Run Dig  # opens first connection
  ${dig_handles} =  Create List
  FOR  ${domain}  IN  facebook.com  microsoft.com  youtube.com  maps.google.com  wikipedia.org  amazon.com
    ${handle} =  Start Dig  ${domain}
    Append To List  ${dig_handles}  ${handle}
  END
  FOR  ${handle}  IN  @{dig_handles}
    Stop Dig  ${handle}
  END
  Set To Dictionary  ${expected_logs}  curl opened socket=1  # curl must not open more sockets then 1
