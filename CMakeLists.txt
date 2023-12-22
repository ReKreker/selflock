cmake_minimum_required(VERSION 3.26)
project(selflock C)

set(CMAKE_C_STANDARD 11)

add_executable(selflock main.c
        sl.c
        sl.h)

target_link_libraries(selflock PUBLIC inotifytools)
