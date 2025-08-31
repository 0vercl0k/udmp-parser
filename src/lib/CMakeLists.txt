# Axel '0vercl0k' Souchet - January 22 2022
add_library(udmp-parser INTERFACE)
target_include_directories(udmp-parser INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
    target_compile_definitions(udmp-parser INTERFACE NOMINMAX)
endif()

if(UDMP_PARSER_INSTALL)
    install(FILES $<TARGET_PROPERTY:udmp-parser,INTERFACE_INCLUDE_DIRECTORIES>/udmp-parser.h DESTINATION inc)
endif(UDMP_PARSER_INSTALL)
