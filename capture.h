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

char *convmac_tostr(unsigned char *, char *, size_t);

void show_ipver(struct iphdr *ip_hdr);

void show_hdrlen(struct iphdr *ip_hdr);

void show_ipprd(struct iphdr *ip_hdr);

void show_dscp(struct iphdr *ip_hdr);

void show_totlen(struct iphdr *ip_hdr);

void show_id(struct iphdr *ip_hdr);

void show_flag(struct iphdr *ip_hdr);

void show_ttl(struct iphdr *ip_hdr);

void show_prot(struct iphdr *ip_hdr);

int ip_checksum(struct iphdr *ip_hdr);

void show_ipaddr(struct iphdr *ip_hdr);