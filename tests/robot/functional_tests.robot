*** Settings ***
Documentation  Simple functional tests for https_dns_proxy
Library        OperatingSystem
Library        Process
Library        Collections
Library        DnsTcpClient.py


*** Variables ***
${BINARY_PATH}  ${CURDIR}/../../https_dns_proxy
${PORT}  55353


*** Settings ***
Test Teardown  Stop Proxy


*** Keywords ***
Common Test Setup
  Set Test Variable  &{expected_logs}  loop destroyed=1  # last log line
  Set Test Variable  @{error_logs}  [F]  # any fatal error
  Set Test Variable  @{dig_options}  +notcp  # UDP only

Start Proxy
  [Arguments]  @{args}
  @{default_args} =  Create List  -v  -v  -v  -4  -p  ${PORT}
  @{proces_args} =  Combine Lists  ${default_args}  ${args}
  ${proxy} =  Start Process  ${BINARY_PATH}  @{proces_args}
  ...  stderr=STDOUT  alias=proxy
  Set Test Variable  ${proxy}
  Set Test Variable  ${dig_timeout}  2
  Set Test Variable  ${dig_retry}  0
  Sleep  0.5
  Common Test Setup

Start Proxy With Valgrind
  [Arguments]  @{args}
  @{default_args} =  Create List  --track-fds=yes  --time-stamp=yes  --log-file=valgrind-%p.log  --suppressions=valgrind.supp
  ...  --gen-suppressions=all  --tool=memcheck  --leak-check=full  --leak-resolution=high
  ...  --show-leak-kinds=all  --track-origins=yes  --keep-stacktraces=alloc-and-free
  ...  ${BINARY_PATH}  -v  -v  -v  -F  100  -4  -p  ${PORT}  # using flight recorder with smallest possible buffer size to test memory leak
  @{proces_args} =  Combine Lists  ${default_args}  ${args}
  ${proxy} =  Start Process  valgrind  @{proces_args}
  ...  stderr=STDOUT  alias=proxy
  Set Test Variable  ${proxy}
  Set Test Variable  ${dig_timeout}  10
  Set Test Variable  ${dig_retry}  2
  Sleep  6  # wait for valgrind to fire up the proxy
  Common Test Setup

Stop Proxy
  Send Signal To Process  SIGINT  ${proxy}
  ${result} =  Wait For Process  ${proxy}  timeout=15 secs
  IF  $result is None
    ${result} =  Terminate Process  ${proxy}  kill=true
  END
  Log  ${result.rc}
  Log  ${result.stdout}
  Log  ${result.stderr}
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
  ${handle} =  Start Process  dig  +timeout\=${dig_timeout}  +retry\=${dig_retry}  @{dig_options}  @127.0.0.1  -p  ${PORT}  ${domain}
  ...  stderr=STDOUT  alias=dig
  RETURN  ${handle}

Stop Dig
  [Arguments]  ${handle}
  ${result} =  Wait For Process  ${handle}  timeout=20 secs
  Log  ${result.stdout}
  Should Be Equal As Integers  ${result.rc}  0
  Should Contain  ${result.stdout}  ANSWER SECTION
  RETURN  ${result.stdout}

Run Dig
  [Arguments]  ${domain}=google.com
  ${handle} =  Start Dig  ${domain}
  ${dig_output} =  Stop Dig  ${handle}
  RETURN  ${dig_output}

Run Dig Parallel
  ${dig_handles} =  Create List
  FOR  ${domain}  IN  facebook.com  microsoft.com  youtube.com  maps.google.com  wikipedia.org  amazon.com
    ${handle} =  Start Dig  ${domain}
    Append To List  ${dig_handles}  ${handle}
  END
  FOR  ${handle}  IN  @{dig_handles}
    Stop Dig  ${handle}
  END

Large Response Test
  [Documentation]  https://dnscheck.tools/#more
  Set Test Variable  @{dig_options}  @{dig_options}  -t  txt  #  ask for TXT response
  ${dig_output} =  Run Dig  txtfill4096.test.dnscheck.tools
  Should Contain  ${dig_output}  MSG SIZE \ rcvd: 4185  # expecting more than 4k large response


*** Test Cases ***
Handle Unbound Server Does Not Support HTTP/1.1
  Start Proxy  -x  -r  https://doh.mullvad.net/dns-query  # resolver uses Unbound
  Run Keyword And Expect Error  9 != 0  # timeout exit code
  ...  Run Dig

Reuse HTTP/2 Connection
  [Documentation]  After first successful request, further requests should not open new connections
  Start Proxy
  Run Dig  # Simple smoke test and opens first connection
  Run Dig Parallel
  Set To Dictionary  ${expected_logs}  curl opened socket=1  # curl must not open more sockets then 1

Valgrind Resource Leak Check
  Start Proxy With Valgrind
  Run Dig Parallel

Valgrind Resource Leak Check TCP
  Start Proxy With Valgrind
  Set Test Variable  @{dig_options}  +tcp  # TCP only
  Run Dig Parallel

Large Response UDP
  Start Proxy
  Large Response Test

Large Response TCP
  Start Proxy
  Set Test Variable  @{dig_options}  +tcp  # TCP only
  Large Response Test

Send TCP Requests Fragmented
  [Documentation]  Check manually the debug logs of dns_server_tcp.c file!
  Start Proxy
  Open Tcp Client Connection  127.0.0.1  ${PORT}

  # send 1st request and start 2nd one
  Send Tcp Request Parts  1
  Sleep  0.01
  Send Tcp Request Parts  2
  Sleep  0.01
  Send Tcp Request Parts  3
  Sleep  0.01
  Send Tcp Request Parts  4  1
  ${dns_reply} =  Receive Tcp Response
  Log  ${dns_reply}
  Should Contain  ${dns_reply}  google

  # send 2nd request and start 3rd one
  Send Tcp Request Parts  2
  Sleep  0.01
  Send Tcp Request Parts  3  4  1  2
  ${dns_reply} =  Receive Tcp Response
  Log  ${dns_reply}
  Should Contain  ${dns_reply}  google

  # finish 3rd request
  Send Tcp Request Parts  3  4
  ${dns_reply} =  Receive Tcp Response
  Log  ${dns_reply}
  Should Contain  ${dns_reply}  google

  Close Tcp Client Connection
