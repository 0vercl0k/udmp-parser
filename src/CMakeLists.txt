# Axel '0vercl0k' Souchet - January 22 2022
# Note: the cmake version must be the same as in python/pyproject.toml::tool.scikit-build:cmake.minimum-version
cmake_minimum_required(VERSION 3.21)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_POSITION_INDEPENDENT_CODE True)

project(
    udmp-parser
    DESCRIPTION "A Cross-Platform C++ parser library for Windows user minidumps."
    HOMEPAGE_URL https://github.com/0vercl0k/udmp-parser
    VERSION 0.6.0
)

set(PROJECT_AUTHOR 0vercl0k)
set(PROJECT_LICENSE MIT)

option(BUILD_PARSER "Build the parser executable for UdmpParser" ${PROJECT_IS_TOP_LEVEL})
option(UDMP_PARSER_INSTALL "Install targets" ${PROJECT_IS_TOP_LEVEL})

add_subdirectory(lib)

if(BUILD_PARSER)
    add_subdirectory(parser)
endif(BUILD_PARSER)
