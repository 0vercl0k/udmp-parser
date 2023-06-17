find_package(Python 3.9
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

nanobind_add_module(udmp_parser NB_STATIC src/udmp_parser.cc)

if(BUILD_PYTHON_PACKAGE)
    #
    # Those directives are only used when creating a standalone `udmp_parser` python package
    #
    target_include_directories(udmp_parser PRIVATE ../lib)
    install(TARGETS udmp_parser LIBRARY DESTINATION .)

else()
    #
    # This is the general case, when built from the root cmakefile
    #
    target_include_directories(udmp_parser PRIVATE $<TARGET_PROPERTY:udmp-parser,INTERFACE_INCLUDE_DIRECTORIES>)
    install(TARGETS udmp_parser DESTINATION bindings/python)

    if(MSVC)
        install(FILES $<TARGET_PDB_FILE:udmp_parser> DESTINATION bindings/python OPTIONAL)
    endif(MSVC)
endif(BUILD_PYTHON_PACKAGE)

if(WIN32)
    target_compile_definitions(udmp_parser PRIVATE NOMINMAX)
endif()
