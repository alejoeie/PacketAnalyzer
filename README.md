# Overview
Packet Analyzer is a command-line tool designed to capture and analyze live network traffic. It focuses on parsing Ethernet and IPv4 headers to provide detailed insights into the captured packets. The tool currently supports live traffic capturing using libpcap and displays information about available network interfaces, including IPv4, IPv6, and subnet masks.

## Architecture
The project is designed with modularity and scalability in mind, ensuring that each functionality is encapsulated within its dedicated module:

### Modules
1. Ethernet Parsing
- Handles the dissection of Ethernet headers, including MAC addresses and protocol type.
- Parses only supported EtherTypes (e.g., IPv4). If the EtherType indicates IPv6, parsing is terminated for that packet.

2. IPv4 Parsing
- Focuses on interpreting IPv4 headers, extracting fields like source and destination IP addresses, TTL, and protocol type.
- Performs sanity checks (e.g., header length validation).

3. PCAP Utilities
- Manages interaction with libpcap, including device discovery and packet capturing.
- Responsible for fetching device details such as IPv4/IPv6 addresses and subnet masks.

4. Main Application
- Orchestrates the flow of data between modules.
- Configures and starts live packet capturing.

### Flow Diagram
```
+-------------------+
|  PacketAnalyzer   |
+-------------------+
         |
         v
+-------------------+
|    PCAP Utilities |
+-------------------+
         |
         v
+-------------------+       +-----------------+
| Ethernet Parsing  |<----->| IPv4 Parsing    |
+-------------------+       +-----------------+
```

## Setup 
1. Install libpcap:
- On EndeavourOS or other Arch-based distros:
``` bash
sudo pacman -S libpcap
```
2. Ensure CMake is installed:
``` bash
sudo pacman -S cmake
```

## Project Structure
```
pkt-src
├── build/                    # Compiled binaries and object files
├── include/                  # Header files
│   ├── pcap_utils/           # Headers for PCAP functionality
│   ├── pkt_analyzer.h        # Main application header
│   ├── pkt_headers.h         # Ethernet and IPv4 header definitions
├── src/                      # Source files
│   ├── pcap_utils/           # PCAP utility implementations
│   ├── pkt_analyzer.c        # Main application logic
├── CMakeLists.txt            # Build configuration
└── packet_analyzer.pc.in     # PCAP configuration template
```

## Building the project
To compile the project using CMake:
1. Create a `build` directory
``` bash
mkdir build && cd build
```
2. Run `CMake` to  configure the project:
``` bash
cmake ..
```
3. Run `make` to compile the code:
``` bash
make
```

## Running the Analyzer
Run the binary:
``` bash
./packet_analyzer
```