# Axel '0vercl0k' Souchet - January 22 2022
add_library(udmp-parser INTERFACE)
target_include_directories(udmp-parser INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

install(FILES $<TARGET_PROPERTY:udmp-parser,INTERFACE_INCLUDE_DIRECTORIES>/udmp-parser.h DESTINATION inc)
