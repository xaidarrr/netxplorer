# CMake version
cmake_minimum_required(VERSION 3.10)

# Project name
project(Netxplorer)

# C and C++
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -D_GNU_SOURCE")

# Directories with files
include_directories(${PROJECT_SOURCE_DIR}/include)

# Files
set(SOURCES
    src/main.cpp
    src/network_utils.c
    src/icmp.c
    src/tcp.c
)

# Creating executable file
add_executable(netxplorer ${SOURCES})