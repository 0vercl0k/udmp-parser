# Axel '0vercl0k' Souchet - January 22 2022
add_executable(parser parser.cc)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(STATUS "Using GCC")
    target_compile_options(parser PRIVATE -Wall -Wextra -Werror -pedantic)

elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(STATUS "Using Clang")
    target_compile_options(parser PRIVATE -Wall -Wextra -Werror -pedantic)

elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    message(STATUS "Using MSVC")
    target_compile_options(parser PRIVATE /W4 /WX)
    target_compile_definitions(parser PRIVATE NOMINMAX)
else()
    message(STATUS "Using ${CMAKE_CXX_COMPILER_ID}")
endif()

target_link_libraries(parser PRIVATE udmp-parser)

if(UDMP_PARSER_INSTALL)
    install(FILES $<TARGET_FILE:parser> DESTINATION bin)

    if(MSVC)
        install(FILES $<TARGET_PDB_FILE:parser> DESTINATION bin OPTIONAL)
    endif(MSVC)
endif()