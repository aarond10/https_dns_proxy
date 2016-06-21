project(HttpsDnsProxy)
cmake_minimum_required(VERSION 2.8)

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
set(LIBS ${LIBS} cares curl ev resolv)
target_link_libraries(${TARGET_NAME} ${LIBS})

install(CODE "MESSAGE(\"Please install manually for now.\")")
