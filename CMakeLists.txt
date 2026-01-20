cmake_minimum_required(VERSION 3.10)
project(Linux_Encrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 仅保留x86_64编译选项，无其他架构内容
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2 -m64")

set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/decryptor_linux.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test_class.cpp
)
add_library(encrypt_core STATIC ${SOURCES})

# 仅支持Linux x86_64
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    target_include_directories(encrypt_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(encrypt_core PRIVATE BUILD_LINUX_VERSION ARCH_X86_64)
    # 仅添加编译必需的dl库链接，无其他多余内容
    target_link_libraries(encrypt_core PRIVATE dl)
else()
    message(FATAL_ERROR "Only Linux x86_64 platform is supported")
endif()

set_target_properties(encrypt_core PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# encrypt_tool 仅x86_64 Linux
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    add_executable(encrypt_tool ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_linux.cpp)
    target_compile_definitions(encrypt_tool PRIVATE BUILD_LINUX_VERSION ARCH_X86_64)
    target_include_directories(encrypt_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(encrypt_tool PRIVATE dl)
    set_target_properties(encrypt_tool PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

# run_test 仅x86_64 Linux，链接逻辑还原为你的写法（仅补dl库）
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    add_executable(run_test 
        ${CMAKE_CURRENT_SOURCE_DIR}/src/run_test.cpp
    )

    target_compile_definitions(run_test PRIVATE BUILD_LINUX_VERSION ARCH_X86_64)
    target_include_directories(run_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    
    # 保留你原来的链接方式，仅补充dl库
    target_link_libraries(run_test 
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/encrypt_core.a
        dl  # 仅添加编译必需的dl库，无其他修改
    )
    
    set_target_properties(run_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()
