# Axel '0vercl0k' Souchet - January 22 2022
link_libraries(udmp-parser)
if (WIN32)
    add_compile_definitions(NOMINMAX)
endif()
add_executable(parser parser.cc)
