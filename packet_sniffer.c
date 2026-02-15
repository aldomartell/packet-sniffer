#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/* ===== PACKET SNIFFER ===== 
 * This program captures network packets and displays their contents
 * Demonstrates: socket programming, network protocols, data structures
 */

// Function to print Ethernet frame information
void print_ethernet_frame(unsigned char *buffer, int size) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    printf("\n=== ETHERNET FRAME ===\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Protocol: %u\n", ntohs(eth->h_proto));
}

// Function to print IPv4 packet information
void print_ipv4_packet(unsigned char *buffer, int size) {
    struct iphdr *ip = (struct iphdr *)buffer;
    unsigned char *ipaddr = (unsigned char *)&ip->saddr;
    
    printf("\n=== IPv4 PACKET ===\n");
    printf("Source IP: %d.%d.%d.%d\n", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    
    ipaddr = (unsigned char *)&ip->daddr;
    printf("Destination IP: %d.%d.%d.%d\n", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    printf("Protocol: %d (", ip->protocol);
    
    // Identify protocol type
    switch (ip->protocol) {
        case 6:
            printf("TCP)\n");
            break;
        case 17:
            printf("UDP)\n");
            break;
        case 1:
            printf("ICMP)\n");
            break;
        default:
            printf("OTHER)\n");
    }
    
    printf("TTL: %d\n", ip->ttl);
    printf("Total Length: %d bytes\n", ntohs(ip->tot_len));
}

// Function to print TCP segment information
void print_tcp_segment(unsigned char *buffer, int size) {
    struct tcphdr *tcp = (struct tcphdr *)buffer;
    
    printf("\n=== TCP SEGMENT ===\n");
    printf("Source Port: %u\n", ntohs(tcp->source));
    printf("Destination Port: %u\n", ntohs(tcp->dest));
    printf("Sequence Number: %u\n", ntohl(tcp->seq));
    printf("Acknowledgement Number: %u\n", ntohl(tcp->ack_seq));
    printf("Flags: ");
    
    // Print TCP flags (SYN, ACK, FIN, RST, etc.)
    if (tcp->syn) printf("SYN ");
    if (tcp->ack) printf("ACK ");
    if (tcp->fin) printf("FIN ");
    if (tcp->rst) printf("RST ");
    if (tcp->psh) printf("PSH ");
    if (tcp->urg) printf("URG ");
    printf("\n");
}

// Function to print UDP datagram information
void print_udp_segment(unsigned char *buffer, int size) {
    struct udphdr *udp = (struct udphdr *)buffer;
    
    printf("\n=== UDP DATAGRAM ===\n");
    printf("Source Port: %u\n", ntohs(udp->source));
    printf("Destination Port: %u\n", ntohs(udp->dest));
    printf("Length: %u bytes\n", ntohs(udp->len));
}

// Function to print ICMP message information
void print_icmp_packet(unsigned char *buffer, int size) {
    struct icmphdr *icmp = (struct icmphdr *)buffer;
    
    printf("\n=== ICMP PACKET ===\n");
    printf("Type: %d (", icmp->type);
    
    // Identify ICMP type
    switch (icmp->type) {
        case ICMP_ECHO:
            printf("Echo Request)\n");
            break;
        case ICMP_ECHOREPLY:
            printf("Echo Reply)\n");
            break;
        default:
            printf("OTHER)\n");
    }
    
    printf("Code: %d\n", icmp->code);
    printf("Checksum: %u\n", ntohs(icmp->checksum));
}

// Function to print raw packet data in hexadecimal
void print_hex_data(unsigned char *buffer, int size) {
    printf("\n=== PAYLOAD (first 64 bytes) ===\n");
    int limit = (size < 64) ? size : 64;
    
    for (int i = 0; i < limit; i++) {
        printf("%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

// Main function - packet capture loop
int main(int argc, char *argv[]) {
    // Create a raw socket to capture packets
    // AF_PACKET: work with packet interface
    // SOCK_RAW: capture all packets
    // htons(ETH_P_IP): capture only IP packets
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    
    if (sock < 0) {
        perror("Socket creation failed. Did you run with sudo?");
        return 1;
    }
    
    printf("Packet Sniffer Started (Press Ctrl+C to stop)\n");
    printf("Note: This requires root privileges (sudo)\n");
    printf("================================================\n");
    
    unsigned char buffer[65536]; // Buffer to store packet data
    int packet_count = 0;
    
    // Infinite loop to capture packets
    while (1) {
        int data_size = recvfrom(sock, buffer, 65536, 0, NULL, NULL);
        
        if (data_size < 0) {
            perror("recvfrom failed");
            return 1;
        }
        
        packet_count++;
        printf("\n### PACKET #%d (Size: %d bytes) ###\n", packet_count, data_size);
        
        // Print Ethernet frame
        print_ethernet_frame(buffer, data_size);
        
        // Extract and print IP header (starts after Ethernet header = 14 bytes)
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        print_ipv4_packet((unsigned char *)ip, data_size - sizeof(struct ethhdr));
        
        // Get the IP header length to find where payload starts
        int ip_header_len = ip->ihl * 4;
        unsigned char *ip_payload = (unsigned char *)ip + ip_header_len;
        
        // Process based on protocol
        switch (ip->protocol) {
            case 6: // TCP
                print_tcp_segment(ip_payload, data_size - sizeof(struct ethhdr) - ip_header_len);
                break;
            case 17: // UDP
                print_udp_segment(ip_payload, data_size - sizeof(struct ethhdr) - ip_header_len);
                break;
            case 1: // ICMP
                print_icmp_packet(ip_payload, data_size - sizeof(struct ethhdr) - ip_header_len);
                break;
        }
        
        // Print first 64 bytes of payload data
        print_hex_data(ip_payload, data_size - sizeof(struct ethhdr) - ip_header_len);
    }
    
    close(sock);
    return 0;
}
