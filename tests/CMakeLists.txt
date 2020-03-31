cmake_minimum_required(VERSION 3.12)

include("deps/CMakeUtils/CMakeUtils.cmake")

set(OUTPUT_PAK_DIR "${CMAKE_CURRENT_BINARY_DIR}/pak")
set(OUTPUT_PAK_PATH "${OUTPUT_PAK_DIR}/data.7z")
file(MAKE_DIRECTORY ${OUTPUT_PAK_DIR})
file(COPY "${CMAKE_SOURCE_DIR}/tests/testdata.txt" DESTINATION "${OUTPUT_PAK_DIR}")

execute_process(
    COMMAND ${CMAKE_COMMAND} -E tar "cfv" ${OUTPUT_PAK_PATH} --format=7zip "${OUTPUT_PAK_DIR}/testdata.txt"
    WORKING_DIRECTORY ${OUTPUT_PAK_DIR}
)

file_intern(${OUTPUT_PAK_PATH} pak_data pak_data_c)

add_executable(test_unzip test_unzip.c ${pak_data_c})
target_link_libraries(test_unzip un7z)
add_test(NAME test_unzip COMMAND test_unzip)
set_property(
	TEST test_unzip
	PROPERTY PASS_REGULAR_EXPRESSION "^Hello, World!"
)
