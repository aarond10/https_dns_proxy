project(HttpsDnsProxy)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_BUILD_TYPE "Release")

# set(CMAKE_C_FLAGS "-Wall --pedantic -Wno-strict-aliasing")

find_path(LIBCARES_INCLUDE_DIR ares.h)
find_path(LIBCURL_INCLUDE_DIR curl/curl.h)
find_path(LIBEV_INCLUDE_DIR ev.h)
include_directories(
  ${LIBCARES_INCLUDE_DIR} ${LIBCURL_INCLUDE_DIR}
  ${LIBEV_INCLUDE_DIR} ${NXJSON_DIR} src lib)

find_program(
  CLANG_TIDY_EXE
  NAMES "clang-tidy"
  DOC "Path to clang-tidy executable"
  )
if(NOT CLANG_TIDY_EXE)
  message(STATUS "clang-tidy not found.")
else()
  message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
  set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "-fix" "-checks=*,-clang-analyzer-alpha.*,-misc-unused-parameters,-cert-err34-c,-google-readability-todo,-hicpp-signed-bitwise")
endif()

# The main binary
set(TARGET_NAME "https_dns_proxy")
aux_source_directory(src SRC_LIST)
set(SRC_LIST ${SRC_LIST})
add_executable(${TARGET_NAME} ${SRC_LIST})
add_subdirectory(lib)
set(LIBS ${LIBS} cares curl ev resolv nxjson)
target_link_libraries(${TARGET_NAME} ${LIBS})

# clang-tidy
set_target_properties(
  ${TARGET_NAME} PROPERTIES
  COMPILE_FLAGS "${WARNING_FLAGS}"
)

if(CLANG_TIDY_EXE)
  set_target_properties(
    ${TARGET_NAME} PROPERTIES
    C_CLANG_TIDY "${DO_CLANG_TIDY}"
  )
endif()

find_package(GTest)
if (GTEST_FOUND)
  message(STATUS "gtest found. Enabling tests.")
  enable_testing()
  
  file(GLOB TEST_SRC_FILES ${PROJECT_SOURCE_DIR}/test/*.cc)
  foreach(_test_file ${TEST_SRC_FILES})
      get_filename_component(_test_name ${_test_file} NAME_WE)
      add_executable(${_test_name} ${_test_file} "src/utils.c" "src/logging.c")
      target_link_libraries(${_test_name} gtest ev ${CMAKE_THREAD_LIBS_INIT})
      add_test(${_test_name} ${_test_name})
      set_tests_properties(${_test_name} PROPERTIES TIMEOUT 5)
  endforeach()
endif()

install(CODE "MESSAGE(\"Please install manually for now.\")")
