project(HttpsDnsProxy C)
cmake_minimum_required(VERSION 3.7)

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

set(CMAKE_C_FLAGS "-Wall -Wextra --pedantic -Wno-strict-aliasing -Wno-variadic-macros")
set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2")

if ((CMAKE_C_COMPILER_ID MATCHES GNU   AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 9) OR
    (CMAKE_C_COMPILER_ID MATCHES Clang AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10))
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-folding-constant")
endif()

# VERSION

find_package(Git)
if(Git_FOUND)
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" show --date=format:%Y.%m.%d --format=%ad-%h --no-patch
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message(STATUS "Version: ${GIT_VERSION}")

  # May not update version in some cases (example: git commit --amend)
  set_property(GLOBAL APPEND
    PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/.git/index")
else()
  set(GIT_VERSION "UNKNOWN")
  message(WARNING "Could not find git command! Version is set to: ${GIT_VERSION}")
endif()

# LIBRARY DEPENDENCIES

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

# CLANG TIDY

find_program(
  CLANG_TIDY_EXE
  NAMES "clang-tidy"
  DOC "Path to clang-tidy executable"
  )
if(NOT CLANG_TIDY_EXE)
  message(STATUS "clang-tidy not found.")
else()
  message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
  set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "-fix" "-checks=*,-clang-analyzer-alpha.*,-misc-unused-parameters,-cert-err34-c,-google-readability-todo,-hicpp-signed-bitwise,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-gnu-folding-constant,-gnu-zero-variadic-macro-arguments,-readability-function-cognitive-complexity,-concurrency-mt-unsafe")
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

set_source_files_properties(
  src/main.c src/options.c
  PROPERTIES COMPILE_FLAGS "-DGIT_VERSION='\"${GIT_VERSION}\"'")

if(CLANG_TIDY_EXE)
  set_target_properties(
    ${TARGET_NAME} PROPERTIES
    C_CLANG_TIDY "${DO_CLANG_TIDY}"
  )
endif()

# INSTALL

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

set(SERVICE_EXTRA_OPTIONS "")
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

find_program(
  PYTHON3_EXE
  NAMES "python3"
  DOC "Path to python3 executable"
  )
if(NOT PYTHON3_EXE)
  message(STATUS "python3 not found, robot testing not possible")
else()
  message(STATUS "python3 found: ${PYTHON3_EXE}")

  enable_testing()
  add_test(NAME robot COMMAND ${PYTHON3_EXE} -m robot.run functional_tests.robot
           WORKING_DIRECTORY tests/robot)
endif()
