#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define ETHERTYPE_RRCP 0x8899

#define DPCP_RCV_MAXSIZE 68
#define DPCP_PROMSCS_MODE 1
#define DPCP_RCV_TIMEOUT 1000
#define DPCP_NOLIMIT_LOOP -1
#define DPCP_IPV4_PKT 0x04
#define DPCP_IPV6_PKT 0x06

#define DPCP_PROT_ICMP 0x01
#define DPCP_PROT_TCP 0x06
#define DPCP_PROT_UDP 0x11

#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

void start_packet_function(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

void print_ether_header(const unsigned char *p);

void print_ip_header(const unsigned char *p);

char *convmac_tostr(unsigned char *, char *, size_t);

void print_ipver(struct iphdr *ip_hdr);

void print_hdrlen(struct iphdr *ip_hdr);

void print_ipprd(struct iphdr *ip_hdr);

void print_dscp(struct iphdr *ip_hdr);

void print_totlen(struct iphdr *ip_hdr);

void print_id(struct iphdr *ip_hdr);

void print_flag(struct iphdr *ip_hdr);

void print_ttl(struct iphdr *ip_hdr);

void print_prot(struct iphdr *ip_hdr, const unsigned char *p);

void print_icmp_header(const unsigned char *p);

void print_tcp_header(const unsigned char *p);

void print_udp_header(const unsigned char *p);

int calc_ip_checksum(struct iphdr *ip_hdr);

void print_ipaddr(struct iphdr *ip_hdr);

void print_arp_header(const unsigned char *p);

void print_hardware_type(struct arphdr *arp_hdr);

void print_arp_prot(struct arphdr *arp_hdr);

void print_arp_operation(struct arphdr *arp_hdr);