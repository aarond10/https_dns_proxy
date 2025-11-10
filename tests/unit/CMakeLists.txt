# Unit tests for https_dns_proxy

# Test for logging context
add_executable(test_logging
    test_logging.c
    ../../src/logging.c
    ../../src/ring_buffer.c
)

target_include_directories(test_logging PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(test_logging
    ev
)

# Add test to CTest
add_test(NAME test_logging COMMAND test_logging)

# Set up test properties
set_tests_properties(test_logging PROPERTIES
    TIMEOUT 10
    LABELS "unit"
)
