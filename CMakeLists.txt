cmake_minimum_required(VERSION 3.26)
project(selflock C)

set(CMAKE_C_STANDARD 11)

# Extensions
add_subdirectory(ext/zlog)

# Runtime linked library with rules
add_library(config MODULE src/config.c)
target_include_directories(config PRIVATE src/include)

# Source code
add_library(sources STATIC src/match.c src/sl.c src/utils.c)
target_include_directories(sources PRIVATE src/include
        PRIVATE ext/zlog/src)
target_link_libraries(sources INTERFACE config
        PRIVATE zlog)

add_executable(selflock main.c)
target_link_libraries(selflock PRIVATE sources)