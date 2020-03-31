cmake_minimum_required(VERSION 3.12)

include("deps/CMakeUtils/CMakeUtils.cmake")

set(OUTPUT_PAK_DIR "${CMAKE_CURRENT_BINARY_DIR}/pak")
set(OUTPUT_PAK_PATH "${OUTPUT_PAK_DIR}/data.7z")
file(MAKE_DIRECTORY ${OUTPUT_PAK_DIR})
file(COPY "${CMAKE_SOURCE_DIR}/tests/testdata/" DESTINATION "${OUTPUT_PAK_DIR}")
file(GLOB testdata RELATIVE "${CMAKE_SOURCE_DIR}/tests/testdata" "${CMAKE_SOURCE_DIR}/tests/testdata/*")

execute_process(
    COMMAND ${CMAKE_COMMAND} -E tar "cfv" ${OUTPUT_PAK_PATH} --format=7zip ${testdata}
    WORKING_DIRECTORY ${OUTPUT_PAK_DIR}
)

file_intern(${OUTPUT_PAK_PATH} pak_data pak_data_c)

function(new_test name datafile)
	add_executable(${name} ${ARGN})
	target_link_libraries(${name} un7z)
	add_test(NAME ${name} COMMAND ${name} ${datafile})
	FILE(READ "testdata/${datafile}" datafile_text)
	set_property(
		TEST ${name}
		PROPERTY PASS_REGULAR_EXPRESSION "^${datafile_text}\n$"
	)
endfunction()


new_test(test_unzip1 file1.txt test_unzip.c ${pak_data_c})
new_test(test_unzip2 file2.txt test_unzip.c ${pak_data_c})
