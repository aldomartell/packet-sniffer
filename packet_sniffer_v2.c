#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

/* ===== PACKET SNIFFER V2 (using libpcap) ===== 
 * More portable version that works better on WSL
 */

// Print IPv4 address
void print_ip(unsigned char *addr) {
    printf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
}

// Callback function for each packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int packet_count = 0;
    packet_count++;
    
    printf("\n========================================\n");
    printf("### PACKET #%d (Size: %d bytes) ###\n", packet_count, header->len);
    printf("========================================\n");
    
    // Ethernet header
    struct ethhdr *eth = (struct ethhdr *)packet;
    printf("\n=== ETHERNET FRAME ===\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("Protocol: %u (0x%04x)\n", ntohs(eth->h_proto), ntohs(eth->h_proto));
    
    // Only process IP packets
    if (ntohs(eth->h_proto) != 0x0800) {
        printf("[Non-IP packet, skipping]\n");
        return;
    }
    
    // IP header
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    unsigned char *src_ip = (unsigned char *)&ip->saddr;
    unsigned char *dst_ip = (unsigned char *)&ip->daddr;
    
    printf("\n=== IPv4 PACKET ===\n");
    printf("Source IP: %d.%d.%d.%d\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    printf("Dest IP: %d.%d.%d.%d\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
    printf("TTL: %d\n", ip->ttl);
    printf("Total Length: %d bytes\n", ntohs(ip->tot_len));
    printf("Protocol: %d ", ip->protocol);
    
    // Protocol type
    switch (ip->protocol) {
        case 6:
            printf("(TCP)\n");
            break;
        case 17:
            printf("(UDP)\n");
            break;
        case 1:
            printf("(ICMP)\n");
            break;
        default:
            printf("(OTHER)\n");
            return;
    }
    
    // Calculate IP header length
    int ip_header_len = ip->ihl * 4;
    unsigned char *ip_payload = (unsigned char *)ip + ip_header_len;
    
    // TCP
    if (ip->protocol == 6) {
        struct tcphdr *tcp = (struct tcphdr *)ip_payload;
        printf("\n=== TCP SEGMENT ===\n");
        printf("Source Port: %u\n", ntohs(tcp->source));
        printf("Destination Port: %u\n", ntohs(tcp->dest));
        printf("Sequence: %u\n", ntohl(tcp->seq));
        printf("Ack: %u\n", ntohl(tcp->ack_seq));
        printf("Flags: ");
        if (tcp->syn) printf("SYN ");
        if (tcp->ack) printf("ACK ");
        if (tcp->fin) printf("FIN ");
        if (tcp->rst) printf("RST ");
        if (tcp->psh) printf("PSH ");
        printf("\n");
    }
    
    // UDP
    else if (ip->protocol == 17) {
        struct udphdr *udp = (struct udphdr *)ip_payload;
        printf("\n=== UDP DATAGRAM ===\n");
        printf("Source Port: %u\n", ntohs(udp->source));
        printf("Destination Port: %u\n", ntohs(udp->dest));
        printf("Length: %u bytes\n", ntohs(udp->len));
    }
    
    // ICMP
    else if (ip->protocol == 1) {
        struct icmphdr *icmp = (struct icmphdr *)ip_payload;
        printf("\n=== ICMP PACKET ===\n");
        printf("Type: %d\n", icmp->type);
        printf("Code: %d\n", icmp->code);
    }
    
    // Print first 32 bytes of payload in hex
    printf("\n=== PAYLOAD (first 32 bytes) ===\n");
    int payload_len = header->len - sizeof(struct ethhdr) - ip_header_len;
    if (payload_len > 0) {
        int limit = (payload_len < 32) ? payload_len : 32;
        for (int i = 0; i < limit; i++) {
            printf("%02x ", ip_payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 mask, net;
    
    // Get default network device
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
    
    printf("Packet Sniffer v2 (using libpcap)\n");
    printf("Listening on interface: %s\n", dev);
    printf("Press Ctrl+C to stop\n");
    printf("================================================\n");
    
    // Get network device info
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open device for sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    
    // Compile and apply filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    
    printf("Filter set to: %s\n", filter_exp);
    printf("================================================\n");
    
    // Start packet capture loop
    pcap_loop(handle, -1, packet_handler, NULL);
    
    pcap_freecode(&fp);
    pcap_close(handle);
    
    return 0;
}
