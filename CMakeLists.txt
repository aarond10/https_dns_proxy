cmake_minimum_required(VERSION 3.10)
project(HttpsDnsProxy C)

include(CheckIncludeFile)

# FUNCTIONS

# source: https://stackoverflow.com/a/27990434
function(define_file_basename_for_sources targetname)
  get_target_property(source_files "${targetname}" SOURCES)
  foreach(sourcefile ${source_files})
    get_filename_component(basename "${sourcefile}" NAME)
    set_property(
      SOURCE "${sourcefile}" APPEND
      PROPERTY COMPILE_DEFINITIONS "__FILENAME__=\"${basename}\"")
  endforeach()
endfunction()

# CONFIG

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
  message(STATUS "Setting build type to '${CMAKE_BUILD_TYPE}' as none was specified.")
endif()

if (NOT CMAKE_INSTALL_BINDIR)
  set(CMAKE_INSTALL_BINDIR bin)
endif()

string(APPEND CMAKE_C_FLAGS " -Wall -Wextra -Wpedantic -Wstrict-aliasing -Wformat=2 -Wunused -Wno-variadic-macros")
string(APPEND CMAKE_C_FLAGS " -Wnull-dereference -Wshadow -Wconversion -Wsign-conversion -Wfloat-conversion -Wundef")
string(APPEND CMAKE_C_FLAGS " -Wimplicit-fallthrough -Wstrict-overflow=2 -Wredundant-decls -Wdouble-promotion")
string(APPEND CMAKE_C_FLAGS " -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE")

set(CMAKE_C_FLAGS_DEBUG "-gdwarf-4 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE")
if (NOT APPLE)  # ld64 doesn't support -z; PIE binaries are the macOS default anyway
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
endif()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
string(APPEND CMAKE_C_FLAGS " -Warray-bounds=2 -Wduplicated-cond -Wduplicated-branches -Wrestrict")
endif()
if (CMAKE_C_COMPILER_ID MATCHES Clang)
string(APPEND CMAKE_C_FLAGS " -Wno-format-nonliteral -Wno-double-promotion")
endif()
if (((CMAKE_C_COMPILER_ID MATCHES GNU   AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL  9) AND
     (CMAKE_C_COMPILER_ID MATCHES GNU   AND CMAKE_C_COMPILER_VERSION VERSION_LESS          14)) OR
    ( CMAKE_C_COMPILER_ID MATCHES Clang AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10))
string(APPEND CMAKE_C_FLAGS " -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-folding-constant")
endif()

set(SERVICE_EXTRA_OPTIONS "")
set(SERVICE_TYPE "simple")

# VERSION
# It is possible to define external default value like: cmake -DSW_VERSION=1.2-custom

find_package(Git)
if(Git_FOUND)
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" show --date=format:%Y.%m.%d --format=%ad-%h --no-patch
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  if(GIT_VERSION)
    set(SW_VERSION "${GIT_VERSION}")
  else()
    message(WARNING "Could not find out version from git command!")
  endif()

  # May not update version in some cases (example: git commit --amend)
  set_property(GLOBAL APPEND
    PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/.git/index")
else()
  message(WARNING "Could not find git command!")
endif()

if(NOT SW_VERSION)
  message(WARNING "Version unset, using hardcoded!")
endif()

# LIBRARY DEPENDENCIES

# Add Homebrew paths for macOS
if(APPLE)
  list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")
  link_directories("/opt/homebrew/lib")
endif()

find_path(LIBCARES_INCLUDE_DIR ares.h)
find_path(LIBEV_INCLUDE_DIR ev.h)

if(CUSTOM_LIBCURL_INSTALL_PATH)
  message(STATUS "Using custom libcurl from: ${CUSTOM_LIBCURL_INSTALL_PATH}")
  set(LIBCURL_INCLUDE_DIR "${CUSTOM_LIBCURL_INSTALL_PATH}/include")
  link_directories(BEFORE "${CUSTOM_LIBCURL_INSTALL_PATH}/lib")
else()
  message(STATUS "Using system libcurl")
  find_path(LIBCURL_INCLUDE_DIR curl/curl.h)
endif()

include_directories(
  ${LIBCARES_INCLUDE_DIR} ${LIBCURL_INCLUDE_DIR}
  ${LIBEV_INCLUDE_DIR} src)

check_include_file("systemd/sd-daemon.h" HAVE_SD_DAEMON_H)

if(HAVE_SD_DAEMON_H)
  message(STATUS "Using libsystemd")
  add_definitions(-DHAS_LIBSYSTEMD=1)
  set(LIBS ${LIBS} systemd)
  set(SERVICE_TYPE "notify")
endif()

# CLANG TIDY

option(USE_CLANG_TIDY "Use clang-tidy during compilation" ON)

if(USE_CLANG_TIDY)
  find_program(
    CLANG_TIDY_EXE
    NAMES "clang-tidy"
    DOC "Path to clang-tidy executable"
    )
  if(NOT CLANG_TIDY_EXE)
    message(STATUS "clang-tidy not found.")
  else()
    message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
    # Opt in to the check modules relevant to portable C instead of "*": the
    # wildcard also enables domain-specific modules (altera-* for FPGA/OpenCL
    # kernels, llvmlibc-*, android-*, ...) whose fixits have previously written
    # inappropriate attributes into this codebase via -fix (see altera-struct-
    # pack-align: extended alignment is UB on calloc'd structs, and packing
    # misaligns embedded sockaddr_storage/libev watchers).
    set(CLANG_TIDY_CHECKS "-checks=-*,bugprone-*,cert-*,clang-analyzer-*,concurrency-*,")
    string(APPEND CLANG_TIDY_CHECKS "misc-*,performance-*,portability-*,readability-*,")
    string(APPEND CLANG_TIDY_CHECKS "-readability-identifier-length,-concurrency-mt-unsafe,")
    string(APPEND CLANG_TIDY_CHECKS "-bugprone-easily-swappable-parameters,-*magic-numbers,")
    string(APPEND CLANG_TIDY_CHECKS "-readability-function-cognitive-complexity,-misc-include-cleaner,")
    string(APPEND CLANG_TIDY_CHECKS "-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,")
    string(APPEND CLANG_TIDY_CHECKS "-*function-size,-clang-diagnostic-*variadic-macro-arguments*")
    set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "${CLANG_TIDY_CHECKS}")
  endif()
else()
  message(STATUS "Not using clang-tidy.")
endif()

# BUILD

# The main binary
set(TARGET_NAME "https_dns_proxy")
aux_source_directory(src SRC_LIST)
set(SRC_LIST ${SRC_LIST})
add_executable(${TARGET_NAME} ${SRC_LIST})
set(LIBS ${LIBS} cares curl ev resolv)
target_link_libraries(${TARGET_NAME} ${LIBS})
set_property(TARGET ${TARGET_NAME} PROPERTY C_STANDARD 11)

define_file_basename_for_sources("https_dns_proxy")


if(SW_VERSION)
  set_source_files_properties(
    src/main.c
    PROPERTIES COMPILE_FLAGS "-DSW_VERSION='\"${SW_VERSION}\"'")
endif()

if(CLANG_TIDY_EXE)
  set_target_properties(
    ${TARGET_NAME} PROPERTIES
    C_CLANG_TIDY "${DO_CLANG_TIDY}"
  )
endif()

# INSTALL

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

if(IS_DIRECTORY "/etc/munin/plugins" AND
   IS_DIRECTORY "/etc/munin/plugin-conf.d")
  set(SERVICE_EXTRA_OPTIONS "-s 300")
  install(PROGRAMS munin/${TARGET_NAME}.plugin
          DESTINATION /etc/munin/plugins/
          RENAME ${TARGET_NAME})
  install(FILES munin/${TARGET_NAME}.config
          DESTINATION /etc/munin/plugin-conf.d/
          RENAME ${TARGET_NAME})
endif()

configure_file(${TARGET_NAME}.service.in ${TARGET_NAME}.service)

install(FILES ${CMAKE_BINARY_DIR}/${TARGET_NAME}.service
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/)

# TESTING

option(BUILD_TESTING "Build tests" OFF)
include(CTest)
if(BUILD_TESTING)
  add_executable(dns_poller_watchers_test
    tests/unit/test_dns_poller.c
    src/logging.c
    src/outbound_interface.c
    src/ring_buffer.c)
  set_property(SOURCE tests/unit/test_dns_poller.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="dns_poller_test")
  target_link_libraries(dns_poller_watchers_test cares ev)
  set_property(TARGET dns_poller_watchers_test PROPERTY C_STANDARD 11)
  add_test(NAME dns_poller_watchers COMMAND dns_poller_watchers_test)
  set_tests_properties(dns_poller_watchers PROPERTIES LABELS unit)

  add_executable(dns_truncate_test
    tests/unit/test_dns_truncate.c
    src/dns_truncate.c
    src/logging.c
    src/ring_buffer.c)
  set_property(SOURCE tests/unit/test_dns_truncate.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="dns_truncate_test")
  target_link_libraries(dns_truncate_test cares ev)
  set_property(TARGET dns_truncate_test PROPERTY C_STANDARD 11)
  add_test(NAME dns_truncate COMMAND dns_truncate_test)
  set_tests_properties(dns_truncate PROPERTIES LABELS unit)

  add_executable(resolver_update_test
    tests/unit/test_resolver_update.c
    src/logging.c
    src/ring_buffer.c)
  set_property(SOURCE tests/unit/test_resolver_update.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="resolver_update_test")
  target_link_libraries(resolver_update_test curl ev)
  set_property(TARGET resolver_update_test PROPERTY C_STANDARD 11)
  add_test(NAME resolver_update COMMAND resolver_update_test)
  set_tests_properties(resolver_update PROPERTIES LABELS unit)

  add_executable(dns_listener_tcp_test
    tests/unit/test_dns_listener_tcp.c
    src/logging.c
    src/ring_buffer.c)
  set_property(SOURCE tests/unit/test_dns_listener_tcp.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="dns_listener_tcp_test")
  target_link_libraries(dns_listener_tcp_test ev)
  set_property(TARGET dns_listener_tcp_test PROPERTY C_STANDARD 11)
  add_test(NAME dns_listener_tcp COMMAND dns_listener_tcp_test)
  set_tests_properties(dns_listener_tcp PROPERTIES LABELS unit TIMEOUT 20)

  add_executable(https_client_limits_test
    tests/unit/test_https_client_limits.c
    src/logging.c
    src/outbound_interface.c
    src/ring_buffer.c
    src/stat.c)
  set_property(SOURCE tests/unit/test_https_client_limits.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="https_client_limits_test")
  target_link_libraries(https_client_limits_test curl ev m)
  set_property(TARGET https_client_limits_test PROPERTY C_STANDARD 11)
  add_test(NAME https_client_limits COMMAND https_client_limits_test)
  set_tests_properties(https_client_limits PROPERTIES LABELS unit)

  add_executable(doh_proxy_resolver_test
    tests/unit/test_doh_proxy_resolver.c
    src/logging.c
    src/ring_buffer.c)
  set_property(SOURCE tests/unit/test_doh_proxy_resolver.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="doh_proxy_resolver_test")
  target_link_libraries(doh_proxy_resolver_test curl ev)
  set_property(TARGET doh_proxy_resolver_test PROPERTY C_STANDARD 11)
  add_test(NAME doh_proxy_resolver COMMAND doh_proxy_resolver_test)
  set_tests_properties(doh_proxy_resolver PROPERTIES LABELS unit)

  add_executable(outbound_interface_test
    tests/unit/test_outbound_interface.c)
  set_property(SOURCE tests/unit/test_outbound_interface.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="outbound_interface_test")
  set_property(TARGET outbound_interface_test PROPERTY C_STANDARD 11)
  add_test(NAME outbound_interface COMMAND outbound_interface_test)
  set_tests_properties(outbound_interface PROPERTIES LABELS unit)

  add_executable(options_test
    tests/unit/test_options.c)
  set_property(SOURCE tests/unit/test_options.c APPEND
    PROPERTY COMPILE_DEFINITIONS __FILENAME__="options_test")
  set_property(TARGET options_test PROPERTY C_STANDARD 11)
  add_test(NAME options COMMAND options_test)
  set_tests_properties(options PROPERTIES LABELS unit)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(outbound_interface_linux_test
      tests/linux/test_outbound_interface_linux.c
      src/outbound_interface.c)
    target_include_directories(outbound_interface_linux_test PRIVATE tests/unit)
    set_property(SOURCE tests/linux/test_outbound_interface_linux.c APPEND
      PROPERTY COMPILE_DEFINITIONS __FILENAME__="outbound_interface_linux_test")
    set_property(TARGET outbound_interface_linux_test PROPERTY C_STANDARD 11)
    add_test(NAME outbound_interface_linux COMMAND outbound_interface_linux_test)
    set_tests_properties(outbound_interface_linux PROPERTIES
      SKIP_RETURN_CODE 77
      LABELS linux-privileged)
  endif()

  find_program(VALGRIND_EXE NAMES valgrind)
  if(VALGRIND_EXE)
    add_test(NAME dns_truncate_valgrind
      COMMAND ${VALGRIND_EXE}
        --error-exitcode=1
        --leak-check=full
        --show-leak-kinds=definite,indirect
        $<TARGET_FILE:dns_truncate_test>)
    set_tests_properties(dns_truncate_valgrind PROPERTIES LABELS memcheck)
  endif()

  find_program(
    PYTHON3_EXE
    NAMES "python3"
    DOC "Path to python3 executable"
    )
  if(NOT PYTHON3_EXE)
    message(STATUS "python3 not found, robot testing not possible")
  else()
    message(STATUS "python3 found: ${PYTHON3_EXE}")

    find_program(OPENSSL_EXE NAMES openssl)
    if(OPENSSL_EXE)
      add_test(NAME tcp_lifecycle
        COMMAND ${PYTHON3_EXE} ${CMAKE_SOURCE_DIR}/tests/integration/test_tcp_lifecycle.py
          --binary $<TARGET_FILE:https_dns_proxy> --openssl ${OPENSSL_EXE})
      set_tests_properties(tcp_lifecycle PROPERTIES LABELS integration TIMEOUT 90)
      if(VALGRIND_EXE)
        add_test(NAME tcp_lifecycle_valgrind
          COMMAND ${PYTHON3_EXE} ${CMAKE_SOURCE_DIR}/tests/integration/test_tcp_lifecycle.py
            --binary $<TARGET_FILE:https_dns_proxy> --openssl ${OPENSSL_EXE}
            --valgrind ${VALGRIND_EXE})
        set_tests_properties(tcp_lifecycle_valgrind PROPERTIES LABELS memcheck TIMEOUT 120)
      endif()
    endif()

    # Robot framework tests
    add_test(NAME robot COMMAND ${PYTHON3_EXE} -m robot.run functional_tests.robot
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests/robot)
  endif()
endif()

# Clean target (removes entire build directory)
add_custom_target(distclean
  COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
  COMMENT "Removing build directory"
)
