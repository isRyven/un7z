Simple CMake file utils to generate file resources:

CMake usage:
```cmake
cmake_minimum_required(VERSION 3.12)

include("${CMAKE_SOURCE_DIR}/cmake/CMakeUtils.cmake")

# input path, resource name (const name used in c), output var w/ generated output path
file_intern("${CMAKE_CURRENT_SOURCE_DIR}/file1.txt" file1_data file1_data_c)
file_intern("${CMAKE_CURRENT_SOURCE_DIR}/file2.txt" file2_data file2_data_c)

add_executable(app main.c ${file1_data_c} ${file2_data_c})
```

C usage:
```c
extern const unsigned char file1_data[];
extern const unsigned int  file1_data_length;

extern const unsigned char file2_data[];
extern const unsigned int  file2_data_length;
```
