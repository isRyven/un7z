cmake_minimum_required(VERSION 3.12)
project(un7z VERSION 0.1.0 LANGUAGES C CXX)

option(UN7Z_BUILD_TESTS "Build tests" OFF)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall -Wextra -Werror=implicit -Werror=implicit-function-declaration -Werror=implicit-int -Werror=pointer-sign -Werror=pointer-arith")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -ggdb")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -flto -s -O2")
endif()

add_library(un7z STATIC un7z.c)
add_library(un7z_h INTERFACE)
target_include_directories(un7z_h INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(un7z un7z_h)

if (UN7Z_BUILD_TESTS)
	message(STATUS "Enabling un7z tests")
	enable_testing()
	add_subdirectory(tests)
endif()
