project(HttpsDnsProxy)
cmake_minimum_required(VERSION 2.8)

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

set(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_BUILD_TYPE "Release")

#set(CMAKE_C_FLAGS "-Wall -Wextra --pedantic -Wno-strict-aliasing")
set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2")

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

find_path(LIBCARES_INCLUDE_DIR ares.h)
find_path(LIBCURL_INCLUDE_DIR curl/curl.h)
find_path(LIBEV_INCLUDE_DIR ev.h)
include_directories(
  ${LIBCARES_INCLUDE_DIR} ${LIBCURL_INCLUDE_DIR}
  ${LIBEV_INCLUDE_DIR} src)

find_program(
  CLANG_TIDY_EXE
  NAMES "clang-tidy"
  DOC "Path to clang-tidy executable"
  )
if(NOT CLANG_TIDY_EXE)
  message(STATUS "clang-tidy not found.")
else()
  message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
  set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "-fix" "-checks=*,-clang-analyzer-alpha.*,-misc-unused-parameters,-cert-err34-c,-google-readability-todo,-hicpp-signed-bitwise,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers")
endif()

# The main binary
set(TARGET_NAME "https_dns_proxy")
aux_source_directory(src SRC_LIST)
set(SRC_LIST ${SRC_LIST})
add_executable(${TARGET_NAME} ${SRC_LIST})
set(LIBS ${LIBS} cares curl ev resolv)
target_link_libraries(${TARGET_NAME} ${LIBS})

define_file_basename_for_sources("https_dns_proxy")

set_source_files_properties(
  src/options.c PROPERTIES
  COMPILE_FLAGS "-DGIT_VERSION='\"${GIT_VERSION}\"'")

if(CLANG_TIDY_EXE)
  set_target_properties(
    ${TARGET_NAME} PROPERTIES
    C_CLANG_TIDY "${DO_CLANG_TIDY}"
  )
endif()

configure_file(${TARGET_NAME}.service.in ${TARGET_NAME}.service)

install(TARGETS ${TARGET_NAME} DESTINATION bin)
install(FILES ${TARGET_NAME}.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/)
