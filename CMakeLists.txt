cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

project (libmctp)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -Wall \
    -Werror \
    -Wextra \
    -Wunused \
    -Wnull-dereference \
    -Wpointer-to-int-cast \
    -Wformat=2 \
")

# Remove if code fixes
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -Wno-unused-parameter \
    -Wno-sign-compare \
    -Wno-type-limits \
")

add_definitions (-DMCTP_LOG_STDERR)
add_definitions (-DMCTP_HAVE_FILEIO)
add_definitions (-DMCTP_HAVE_STDIO)
add_definitions (-DMCTP_DEFAULT_ALLOC)

add_library (mctp_intel STATIC alloc.c asti3c.c core.c encode_request.c encode_response.c decode_request.c decode_response.c log.c libmctp.h astpcie.c smbus.c)

target_include_directories (mctp_intel PUBLIC
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include/libmctp>)

enable_testing ()

add_executable (test_eid tests/test_eid.c tests/test-utils.c)
target_link_libraries (test_eid mctp_intel)
add_test (NAME eid COMMAND test_eid)

add_executable (test_seq tests/test_seq.c tests/test-utils.c)
target_link_libraries (test_seq mctp_intel)
add_test (NAME seq COMMAND test_seq)

add_executable (test_bridge tests/test_bridge.c tests/test-utils.c)
target_link_libraries (test_bridge mctp_intel)
add_test (NAME bridge COMMAND test_bridge)

add_executable (test_astpcie tests/test_astpcie.c)
target_link_options(test_astpcie PRIVATE -z muldefs)
target_link_libraries (test_astpcie mctp_intel)
add_test (NAME astpcie COMMAND test_astpcie)

add_executable (test_cmds tests/test_cmds.c tests/test-utils.c)
target_link_libraries (test_cmds mctp_intel)
add_test (NAME control_commands COMMAND test_cmds)

add_executable (test_smbus tests/test_smbus.c)
target_link_libraries (test_smbus mctp_intel)
add_test (NAME smbus COMMAND test_smbus)

add_executable (test_binding_private tests/test_binding_private.c)
target_link_libraries (test_binding_private mctp_intel)
add_test (NAME binding_private COMMAND test_binding_private)

add_executable (mctp_astpcie_discovery utils/mctp-astpcie-discovery.c)
target_link_libraries (mctp_astpcie_discovery mctp_intel)

add_executable (test_encode_decode tests/test_encode_decode.c)
target_link_libraries (test_encode_decode mctp_intel)
add_test (NAME encode_decode COMMAND test_encode_decode)

add_executable (test_encode_response tests/test_encode_response.c)
target_link_libraries (test_encode_response mctp_intel)
add_test (NAME encode_response COMMAND test_encode_response)

add_executable (test_encode_request tests/test_encode_request.c)
target_link_libraries (test_encode_request mctp_intel)
add_test (NAME encode_request COMMAND test_encode_request)

add_executable (test_decode_request tests/test_decode_request.c)
target_link_libraries (test_decode_request mctp_intel)
add_test (NAME decode_request COMMAND test_decode_request)

add_executable (test_decode_response tests/test_decode_response.c)
target_link_libraries (test_decode_response mctp_intel)
add_test (NAME decode_response COMMAND test_decode_response)

add_executable (mctp_astpcie_register_type utils/mctp-astpcie-register-type.c)
target_link_libraries (mctp_astpcie_register_type mctp_intel)

add_executable (test_asti3c tests/test_asti3c.c)
set_source_files_properties(tests/test_asti3c.c PROPERTIES COMPILE_FLAGS "-Wno-maybe-uninitialized")
target_link_libraries (test_asti3c mctp_intel)
add_test (NAME asti3c COMMAND test_asti3c)

install (TARGETS mctp_intel DESTINATION lib)
install (FILES libmctp.h libmctp-cmds.h libmctp-encode-request.h libmctp-encode-response.h libmctp-decode-request.h libmctp-decode-response.h libmctp-vdpci.h libmctp-smbus.h libmctp-astpcie.h libmctp-msgtypes.h libmctp-asti3c.h DESTINATION include)

configure_file(
    ${PROJECT_SOURCE_DIR}/libmctp.pc.in
    ${PROJECT_BINARY_DIR}/libmctp.pc
)
INSTALL(FILES ${CMAKE_BINARY_DIR}/libmctp.pc
        DESTINATION lib/pkgconfig)
