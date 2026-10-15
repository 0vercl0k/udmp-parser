add_executable(test-missing-thread-context test-missing-thread-context.cc)
target_link_libraries(test-missing-thread-context PRIVATE udmp-parser)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(test-missing-thread-context PRIVATE -Wall -Wextra -Werror -pedantic)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(test-missing-thread-context PRIVATE -Wall -Wextra -Werror -pedantic)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(test-missing-thread-context PRIVATE /W4 /WX)
    target_compile_definitions(test-missing-thread-context PRIVATE NOMINMAX)
endif()

add_test(NAME missing-thread-context COMMAND test-missing-thread-context)
