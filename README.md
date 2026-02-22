# Packet Sniffer

A low-level network packet capture and analysis tool written in C that demonstrates socket programming, network protocols, and systems-level programming concepts.

## Overview

This packet sniffer captures network packets on the local system and decodes them at multiple layers:
- **Ethernet Frame** (Layer 2) - MAC addresses, protocol types
- **IP Header** (Layer 3) - Source/destination IPs, TTL, protocol type
- **Transport Layer** (Layer 4) - TCP ports, flags (SYN, ACK, FIN, RST); UDP ports; ICMP types
- **Payload** - Raw packet data in hexadecimal

## Features

✅ **Packet Capture** - Uses raw sockets to capture all IP traffic  
✅ **Protocol Parsing** - Decodes Ethernet, IPv4, TCP, UDP, and ICMP  
✅ **TCP Flag Analysis** - Shows SYN, ACK, FIN, RST, PSH, URG flags  
✅ **Payload Inspection** - Displays first 64 bytes of packet data in hex  
✅ **Real-time Output** - Prints each packet as it's captured  

## What You'll Learn

This project demonstrates:
- **C Network Programming**: Raw socket creation (`AF_PACKET`, `SOCK_RAW`)
- **Struct Casting**: Working with binary network data structures
- **Protocol Headers**: Understanding Ethernet, IP, TCP/UDP/ICMP packet structures
- **Byte Order Conversion**: Using `ntohs()` and `ntohl()` for network byte order
- **Systems Programming**: Low-level Linux networking APIs
- **Security Concepts**: How packets are structured, what information is available to sniffers

## Building

### Prerequisites
- Linux/WSL (requires raw socket support)
- GCC compiler
- Standard C libraries

### Compile

```bash
gcc -o packet_sniffer packet_sniffer.c
```

## Running

**On Linux (with sudo):**
```bash
sudo ./packet_sniffer
```

**On WSL (Windows Subsystem for Linux):**
WSL1 supports raw sockets. For WSL2, you may need to use the alternative libpcap version:
```bash
sudo ./packet_sniffer_v2
# (requires: sudo apt-get install libpcap-dev)
```

**Example Usage:**
1. Start the sniffer:
   ```bash
   sudo ./packet_sniffer
   ```

2. In another terminal, generate traffic:
   ```bash
   ping google.com
   curl https://example.com
   ```

3. Watch packets appear in the sniffer output

4. Press `Ctrl+C` to stop

## Output Explanation

```
### PACKET #1 (Size: 66 bytes) ###

=== ETHERNET FRAME ===
Destination MAC: 1e:2b:7a:df:37:14
Source MAC: e2:c2:c3:37:3c:1b
Protocol: 2048

=== IPv4 PACKET ===
Source IP: 10.4.86.134
Destination IP: 21.0.0.86
Protocol: 6 (TCP)
TTL: 61
Total Length: 52 bytes

=== TCP SEGMENT ===
Source Port: 58700
Destination Port: 2024
Sequence Number: 2361639460
Acknowledgement Number: 2405131036
Flags: ACK 

=== PAYLOAD (first 64 bytes) ===
e5 4c 07 e8 8c c3 c2 24 8f 5b 63 1c 80 10 00 a6
...
```

**Key Fields:**
- **MAC Addresses**: Hardware addresses for local network communication
- **IP Addresses**: Network layer identifiers
- **Protocol**: 6 = TCP, 17 = UDP, 1 = ICMP
- **TCP Flags**: SYN (connection start), ACK (acknowledgement), FIN (connection end), RST (reset), PSH (push data), URG (urgent)
- **Payload**: Raw hex data - may be application layer data, HTTP requests, DNS queries, etc.

## Code Structure

### Main Components

**Helper Functions:**
- `print_ethernet_frame()` - Parse and display Layer 2 data
- `print_ipv4_packet()` - Parse and display Layer 3 data
- `print_tcp_segment()` - Parse and display TCP headers
- `print_udp_segment()` - Parse and display UDP headers
- `print_icmp_packet()` - Parse and display ICMP packets
- `print_hex_data()` - Display raw payload bytes

**Main Loop:**
1. Create a raw socket with `AF_PACKET` and `SOCK_RAW`
2. Receive packets with `recvfrom()`
3. Parse each layer using struct casting
4. Print formatted output

### Network Structures Used

```c
struct ethhdr          // Ethernet header from <net/ethernet.h>
struct iphdr           // IPv4 header from <netinet/ip.h>
struct tcphdr          // TCP header from <netinet/tcp.h>
struct udphdr          // UDP header from <netinet/udp.h>
struct icmphdr         // ICMP header from <netinet/ip_icmp.h>
```

## Security Implications

This tool demonstrates:
- **Network Reconnaissance**: Passive data capture shows what traffic is on the wire
- **Privacy Concerns**: Packet sniffing can capture unencrypted data (HTTP, FTP, Telnet)
- **Defense Strategy**: Use encrypted protocols (HTTPS, SSH) to prevent sniffing
- **Intrusion Detection**: IDS/IPS systems use similar techniques to detect malicious traffic

## Important Notes

⚠️ **Root Privileges Required** - Raw socket access requires `sudo`  
⚠️ **Legal Usage** - Only sniff networks you own or have explicit permission to monitor  
⚠️ **Unencrypted Traffic** - This tool can only see unencrypted data in payloads  
⚠️ **WSL Limitations** - WSL2 has limitations with raw sockets; WSL1 works better  

## Troubleshooting

**"Socket creation failed. Did you run with sudo?"**
- Solution: Run with `sudo ./packet_sniffer`

**"Operation not permitted"**
- Solution: You need elevated privileges; use `sudo`
- On WSL2: May need to use the libpcap version instead

**No packets appearing**
- The sniffer may be on a different interface (eth0, wlan0, etc.)
- Try: `sudo ./packet_sniffer` and generate traffic in another terminal

## Future Enhancements

Possible improvements:
- [ ] Filter packets by protocol, IP, or port
- [ ] Save captured packets to PCAP file
- [ ] Detect specific patterns (port scans, DNS queries, HTTP requests)
- [ ] Statistics (packet count, bytes transferred, protocol breakdown)
- [ ] GUI interface using GTK or Qt
- [ ] Inline packet modification (MITM capabilities)

## Learning Resources

- **TCP/IP Explained**: "TCP/IP Illustrated" by Richard Stevens
- **Network Protocols**: "Computer Networking" by Kurose & Ross
- **Raw Sockets**: Linux man pages: `man 7 packet`, `man 2 socket`
- **Packet Structure**: Wireshark documentation on protocol dissection

## Author

Aldo Martell - Cybersecurity Enthusiast, Home Lab Enthusiast


