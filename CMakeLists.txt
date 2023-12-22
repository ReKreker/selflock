cmake_minimum_required(VERSION 3.26)
project(selflock C)

set(CMAKE_C_STANDARD 11)

add_library(sl STATIC sl.h sl.c)
add_executable(selflock main.c)
target_link_libraries(selflock sl)