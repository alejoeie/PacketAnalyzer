add_library(pcap_utils STATIC
    pcap_init.c
)

# Link with libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
target_link_libraries(pcap_utils ${PCAP_LIBRARIES})