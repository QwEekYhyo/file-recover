cmake_minimum_required(VERSION 3.10)

project(file-recover LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_options(/W3 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

if(NOT BUILD_TESTING)
    set(BUILD_TESTING ON)
endif()

file(GLOB_RECURSE SOURCES ${PROJECT_SOURCE_DIR}/src/*.c)

add_executable(file-recover ${SOURCES})
target_include_directories(file-recover PRIVATE ${PROJECT_SOURCE_DIR}/include)
