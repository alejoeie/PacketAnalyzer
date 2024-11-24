cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer VERSION 1.0)

# C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Build flags
set(C_WARNINGS "-Wall -Wstrict-prototypes -Wshadow -Werror")
set(CXX_WARNINGS "-Wall -Wshadow -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 ${C_WARNINGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 ${CXX_WARNINGS}")

set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

include_directories(${INCLUDE_DIR})

# Source files
file(GLOB SOURCES "src/*.c")

add_executable(packet_analyzer ${SOURCES})