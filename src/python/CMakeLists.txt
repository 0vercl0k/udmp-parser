#
# This file is part of udmp-parser project
#
# Released under MIT License, by 0vercl0k - 2023
#
# With contribution from:
# * hugsy - (github.com/hugsy)
#
cmake_minimum_required(VERSION 3.21)

project(
    udmp-parser-python
    DESCRIPTION "A Cross-Platform C++ parser library for Windows user minidumps."
    HOMEPAGE_URL https://github.com/0vercl0k/udmp-parser
    VERSION 0.6.0
)

if(NOT PROJECT_IS_TOP_LEVEL)
    message(FATAL_ERROR "This project is not intended to be used as a sub-project")
endif()

find_package(Python 3
    REQUIRED COMPONENTS Interpreter Development.Module
    OPTIONAL_COMPONENTS Development.SABIModule
)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

execute_process(
    COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE NB_DIR)
list(APPEND CMAKE_PREFIX_PATH "${NB_DIR}")

find_package(nanobind CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 20)

nanobind_add_module(udmp_parser STABLE_ABI src/udmp_parser_utils.cc src/udmp_parser.cc)

if(MSVC)
    target_link_libraries(udmp_parser PRIVATE DbgHelp.lib)
endif(MSVC)

#
# Those directives are only used when creating a standalone `udmp_parser` python package
#
target_include_directories(udmp_parser PRIVATE ../lib)
install(TARGETS udmp_parser LIBRARY DESTINATION .)
install(DIRECTORY udmp_parser-stubs DESTINATION .)

if(WIN32)
    target_compile_definitions(udmp_parser PRIVATE NOMINMAX)
endif()
