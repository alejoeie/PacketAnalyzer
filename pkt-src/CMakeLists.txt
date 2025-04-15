cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer VERSION 1.0)

# C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Build flags
set(C_WARNINGS "-Wall -Wstrict-prototypes -Wshadow -Werror -Wstringop-overflow")
set(CXX_WARNINGS "-Wall -Wshadow -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 ${C_WARNINGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 ${CXX_WARNINGS}")

# Include directories
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
include_directories(${INCLUDE_DIR})

# Add subdirectory
add_subdirectory(src/pcap_utils)

# Collect source files
set(SOURCES
    src/pkt_analyzer.c
    src/pkt_sniffing.c
)

add_executable(packet_analyzer ${SOURCES})

target_link_libraries(packet_analyzer pcap_utils)