project(HttpsDnsProxy)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++")

set(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_BUILD_TYPE "Release")

set(NXJSON_DIR lib/nxjson/)
set(NXJSON_SRC ${NXJSON_DIR}/nxjson.c)

find_path(LIBCARES_INCLUDE_DIR ares.h)
find_path(LIBCURL_INCLUDE_DIR curl/curl.h)
find_path(LIBEV_INCLUDE_DIR ev.h)
include_directories(
  ${LIBCARES_INCLUDE_DIR} ${LIBCURL_INCLUDE_DIR}
  ${LIBEV_INCLUDE_DIR} ${NXJSON_DIR} src)

# The main binary
set(TARGET_NAME "https_dns_proxy")
aux_source_directory(src SRC_LIST)
set(SRC_LIST ${SRC_LIST} ${NXJSON_SRC})
add_executable(${TARGET_NAME} ${SRC_LIST})
set(LIBS ${LIBS} cares curl ev)
target_link_libraries(${TARGET_NAME} ${LIBS})

install(CODE "MESSAGE(\"Please install manually for now.\")")

# Tests 
option(HTTPS_DNS_PROXY_TESTS "Build tests for https_dns_proxy" OFF)
if(HTTPS_DNS_PROXY_TESTS)
  set(TARGET_NAME "dns_packet_test")
  set(SRC_LIST test/dns_packet_test.cc src/dns_packet.cc src/logging.c ${NXJSON_SRC})
  add_executable(${TARGET_NAME} ${SRC_LIST})
  target_link_libraries(${TARGET_NAME} gtest)
endif(HTTPS_DNS_PROXY_TESTS)
