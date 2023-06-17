# Axel '0vercl0k' Souchet - January 22 2022
# Note: the cmake version must be the same as in python/pyproject.toml::tool.scikit-build:cmake.minimum-version
cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_POSITION_INDEPENDENT_CODE True)

project(
    udmp-parser
    DESCRIPTION "A Windows user minidump C++ parser library."
    HOMEPAGE_URL https://github.com/0vercl0k/udmp-parser
    VERSION 0.4
)

set(PROJECT_AUTHOR 0vercl0k)
set(PROJECT_LICENSE MIT)

option(BUILD_PARSER "Build the parser executable for UdmpParser" ON)
option(BUILD_PYTHON_BINDING "Build the Python binding for UdmpParser" ON)

add_subdirectory(lib)

if(BUILD_PARSER)
    add_subdirectory(parser)
endif(BUILD_PARSER)

if(BUILD_PYTHON_BINDING)
    add_subdirectory(python)
endif(BUILD_PYTHON_BINDING)
