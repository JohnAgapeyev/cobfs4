cmake_minimum_required (VERSION 3.13)
project(cobfs4)

set(COBFS4_VERSION_MAJOR 1)
set(COBFS4_VERSION_MINOR 0)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(COBFS4_DEBUG_TARGETS OFF)

set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "")
set(CMAKE_C_FLAGS_MINSIZEREL "")

set(BASE_COMPILE_OPTIONS -pipe -march=native -fcf-protection=full -fstack-protector-strong)
set(WARNINGS -Wall -Wextra -Wpedantic -Wuninitialized -Wundef -Wcast-align -Wstrict-overflow=2 -Wwrite-strings -Wno-format-nonliteral)
set(DEBUG_OPTIONS ${BASE_COMPILE_OPTIONS} -ggdb -g3 -O0)
set(RELEASE_OPTIONS ${BASE_COMPILE_OPTIONS} -O3)

set(CMAKE_C_STANDARD 99)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_LINK_WHAT_YOU_USE ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}")

set(LIBRARY_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ecdh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/elligator.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hmac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ntor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/packet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/random.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/siphash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/stream.c
)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_ecdh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_elligator.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_hmac.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_ntor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_packet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_random.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_siphash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_stream.c
)

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(DIEHARDER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_dieharder.c
)

set(TESTU01_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_u01.c
)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 1.1.1 REQUIRED)

find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} SHARED ${LIBRARY_SOURCES})

target_compile_options(${PROJECT_NAME}
    PRIVATE ${WARNINGS}
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${PROJECT_NAME} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)
target_link_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:-s>")
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/cobfs4.h)

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

IF(COBFS4_DEBUG_TARGETS MATCHES ON)
    add_executable(${PROJECT_NAME}_test ${TEST_SOURCES})
    target_compile_options(${PROJECT_NAME}_test
        PRIVATE ${WARNINGS}
        PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
    target_compile_definitions(${PROJECT_NAME}_test PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")
    target_include_directories(${PROJECT_NAME}_test PRIVATE ${INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME}_test PRIVATE OpenSSL::Crypto Threads::Threads ${PROJECT_NAME})
    target_link_options(${PROJECT_NAME}_test PRIVATE "$<$<CONFIG:RELEASE>:-s>")

    add_executable(${PROJECT_NAME}_dieharder ${DIEHARDER_SOURCES})
    target_compile_options(${PROJECT_NAME}_dieharder
        PRIVATE ${WARNINGS}
        PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
    target_compile_definitions(${PROJECT_NAME}_dieharder PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")
    target_include_directories(${PROJECT_NAME}_dieharder PRIVATE ${INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME}_dieharder PRIVATE OpenSSL::Crypto ${PROJECT_NAME})
    target_link_options(${PROJECT_NAME}_dieharder PRIVATE "$<$<CONFIG:RELEASE>:-s>")

    add_executable(${PROJECT_NAME}_u01 ${TESTU01_SOURCES})
    target_compile_options(${PROJECT_NAME}_u01
        PRIVATE ${WARNINGS}
        PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
    target_compile_definitions(${PROJECT_NAME}_u01 PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")
    target_include_directories(${PROJECT_NAME}_u01 PRIVATE ${INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME}_u01 PRIVATE OpenSSL::Crypto ${PROJECT_NAME} -ltestu01)
    target_link_options(${PROJECT_NAME}_u01 PRIVATE "$<$<CONFIG:RELEASE>:-s>")
ENDIF(COBFS4_DEBUG_TARGETS MATCHES ON)
