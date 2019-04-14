#include "capture.h"

int main(int argc, char *argv[])
{
    pcap_t *pd = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];

    if (argc < 2)
    {
        perror("usage: <if name>\n");
        exit(EXIT_FAILURE);
    }

    if ((pd = pcap_open_live(argv[1], DPCP_RCV_MAXSIZE, DPCP_PROMSCS_MODE, DPCP_RCV_TIMEOUT, ebuf)) == NULL)
    {
        exit(-1);
    }

    if (pcap_loop(pd, DPCP_NOLIMIT_LOOP, start_packet_function, NULL) < 0)
    {
        exit(-1);
    }

    pcap_close(pd);

    return 0;
}

void start_packet_function(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
{
    printf("----Receive Packet----\n");

    print_ether_header(p);

    printf("----END----\n");

    return;
}

void print_ether_header(const unsigned char *p)
{
    struct ether_header *eth_hdr = (struct ether_header *)p;
    char dmac[18] = {0};
    char smac[18] = {0};
    printf("----Ether Header----\n");
    printf("Src MAC : %s\n", convmac_tostr(eth_hdr->ether_shost, smac, sizeof(smac)));
    printf("Dest MAC : %s\n", convmac_tostr(eth_hdr->ether_dhost, dmac, sizeof(dmac)));
    printf("Ether Type : 0x%x\n\n", ntohs(eth_hdr->ether_type));

    switch (ntohs(eth_hdr->ether_type))
    {
    case ETHERTYPE_IP:
        print_ip_header(p);
        break;
    case ETHERTYPE_IPV6:
        printf("----IPv6 Packet Receive----\n");
        break;
    case ETHERTYPE_ARP:
        print_arp_header(p);
        break;
    case ETHERTYPE_RRCP:
        printf("----Realtek Remote Control Protocol Receive----\n");
        break;
    default:
        break;
    }
}

char *convmac_tostr(unsigned char *hwaddr, char *mac, size_t size)
{
    snprintf(mac, size, "%02x:%02x:%02x:%02x:%02x:%02x:", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return mac;
}

void print_ip_header(const unsigned char *p)
{
    struct iphdr *ip_hdr = (struct iphdr *)(p + sizeof(struct ether_header));
    printf("----IPv4 Packet Receive----\n");

    print_ipver(ip_hdr);
    print_hdrlen(ip_hdr);
    print_dscp(ip_hdr);
    print_totlen(ip_hdr);
    print_id(ip_hdr);
    print_flag(ip_hdr);
    print_ttl(ip_hdr);
    print_prot(ip_hdr, p);
    ip_hdr->check = calc_ip_checksum(ip_hdr);
    printf("checksum : %d\n", ip_hdr->check);
    print_ipaddr(ip_hdr);
}

void print_ipver(struct iphdr *ip_hdr)
{
    printf("Version: ");
    if (DPCP_IPV4_PKT == ip_hdr->version)
    {
        printf("IPv4\n");
    }
    else if (DPCP_IPV6_PKT == ip_hdr->version)
    {
        printf("IPv6\n");
    }
    else
    {
        printf("unknown version\n");
    }
}

void print_hdrlen(struct iphdr *ip_hdr)
{
    printf("IP Header Length: %u byte\n", ip_hdr->ihl * 4);
}

void print_ipprd(struct iphdr *ip_hdr)
{
    printf("IP Precedence: ");
    if (0 == ip_hdr->tos & (0xFF & ~IPTOS_CLASS_MASK))
    {
        switch (IPTOS_PREC(ip_hdr->tos))
        {
        case IPTOS_PREC_ROUTINE:
            printf("routine\n");
            break;
        case IPTOS_PREC_PRIORITY:
            printf("priority\n");
        case IPTOS_PREC_IMMEDIATE:
            printf("immediate\n");
            break;
        case IPTOS_PREC_FLASH:
            printf("flash\n");
            break;
        case IPTOS_PREC_FLASHOVERRIDE:
            printf("flash-override\n");
            break;
        case IPTOS_PREC_CRITIC_ECP:
            printf("critical\n");
            break;
        case IPTOS_PREC_INTERNETCONTROL:
            printf("internet\n");
            break;
        case IPTOS_PREC_NETCONTROL:
            printf("network\n");
            break;
        default:
            break;
        }
    }
}

void print_dscp(struct iphdr *ip_hdr)
{
    int dscp = IPTOS_DSCP(ip_hdr->tos);
    printf("Differentiated Services Code Point : ");

    if (dscp != 0)
    {
        printf("\n----\n");
        if (IPTOS_CLASS(dscp) == 0)
        {
            printf("Class Selector : \n");
            print_ipprd(ip_hdr);
        }
        else if (dscp == IPTOS_DSCP_EF)
        {
            printf("Expendited Forwarding: true");
        }
        else
        {
            printf("Assured Forwarding : ");
            switch (dscp)
            {
            case IPTOS_DSCP_AF11:
                printf("af11\n");
                break;
            case IPTOS_DSCP_AF12:
                printf("af12\n");
                break;
            case IPTOS_DSCP_AF13:
                printf("af13\n");
                break;
            case IPTOS_DSCP_AF21:
                printf("af21\n");
                break;
            case IPTOS_DSCP_AF22:
                printf("af22\n");
                break;
            case IPTOS_DSCP_AF23:
                printf("af23\n");
                break;
            case IPTOS_DSCP_AF31:
                printf("af31\n");
                break;
            case IPTOS_DSCP_AF32:
                printf("af32\n");
                break;
            case IPTOS_DSCP_AF33:
                printf("af33\n");
                break;
            case IPTOS_DSCP_AF41:
                printf("af41\n");
                break;
            case IPTOS_DSCP_AF42:
                printf("af42\n");
                break;
            case IPTOS_DSCP_AF43:
                printf("af43\n");
                break;
            default:
                printf("unknown\n");
                break;
            }
        }
    }
    else
    {
        printf("Best effort\n");
    }
}

void print_totlen(struct iphdr *ip_hdr)
{
    printf("total length : %u byte\n", ntohs(ip_hdr->tot_len));
}

void print_id(struct iphdr *ip_hdr)
{
    printf("identification : %u byte\n", ntohs(ip_hdr->id));
}

void print_flag(struct iphdr *ip_hdr)
{
    int flag = ntohs(ip_hdr->frag_off);
    printf("flag : ");
    if (IP_DF == flag)
    {
        printf("Don't Fragment\n");
    }
    else if (IP_MF == flag)
    {
        printf("More Fragment\n");
    }
    else
    {
        printf("Finish Fragment\n");
    }

    printf("flagment offset : %u byte\n", (IP_OFFMASK & flag * 8));
}

void print_ttl(struct iphdr *ip_hdr)
{
    printf("time to live : %u\n", ip_hdr->ttl);
}

void print_prot(struct iphdr *ip_hdr, const unsigned char *p)
{
    printf("Protocol : ");
    if (DPCP_PROT_ICMP == ip_hdr->protocol)
    {
        printf("ICMP\n");
        print_icmp_header(p);
    }
    else if (DPCP_PROT_TCP == ip_hdr->protocol)
    {
        printf("TCP\n");
        print_tcp_header(p);
    }
    else if (DPCP_PROT_UDP == ip_hdr->protocol)
    {
        printf("UDP\n");
        print_udp_header(p);
    }
    else
    {
        printf("0x%x\n", ip_hdr->protocol);
    }
}

void print_icmp_header(const unsigned char *p)
{
    struct icmphdr *icmp_hdr = (struct icmphdr *)(p + sizeof(struct ether_header) + sizeof(struct iphdr));
    printf("    ICMP Header\n");
    printf("        Type : %u ", ntohs(icmp_hdr->type));
    switch (ntohs(icmp_hdr->type))
    {
    case ICMP_ECHOREPLY:
        printf("(ICMP Echo Reply)\n");
        break;
    case ICMP_TIME_EXCEEDED:
        printf("(TTL Expired)\n");
        break;
    default:
        printf("\n");
        break;
    }
    printf("        Code : %u\n", ntohs(icmp_hdr->code));
    printf("        Checksum : %u\n", ntohs(icmp_hdr->checksum));
}

void print_tcp_header(const unsigned char *p)
{
    struct tcphdr *tcp_hdr = (struct tcphdr *)(p + sizeof(struct ether_header) + sizeof(struct iphdr));
    printf("    TCP Header\n");
    printf("        Src Port : %u\n", ntohs(tcp_hdr->th_sport));
    printf("        Dest Port : %u\n", ntohs(tcp_hdr->th_dport));
    printf("        TCP Checksum : %u\n", ntohs(tcp_hdr->th_sum));
}

void print_udp_header(const unsigned char *p)
{
    struct udphdr *udp_hdr = (struct udphdr *)(p + sizeof(struct ether_header) + sizeof(struct iphdr));
    printf("    UDP Header\n");
    printf("        Src Port : %u\n", ntohs(udp_hdr->uh_sport));
    printf("        Dest Port : %u\n", ntohs(udp_hdr->uh_dport));
    printf("        UDP Length : %u bytes\n", ntohs(udp_hdr->uh_ulen));
    printf("        UDP Checksum : %u\n", ntohs(udp_hdr->uh_sum));
}

int calc_ip_checksum(struct iphdr *ip_hdr)
{
    int hdr_len = 0;
    int sum = 0;
    u_int16_t *buf = (u_int16_t *)ip_hdr;

    ip_hdr->check = 0;
    hdr_len = ip_hdr->ihl * 4;

    while (hdr_len > 0)
    {
        sum += *buf++;

        if (sum & 0x80000000)
        {
            exit(-1);
        }

        hdr_len -= 2;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

void print_ipaddr(struct iphdr *ip_hdr)
{
    char ip_str[18] = {0};
    struct in_addr *saddr = NULL;
    struct in_addr *daddr = NULL;

    printf("Source IP : ");
    saddr = (struct in_addr *)&(ip_hdr->saddr);
    inet_ntop(AF_INET, saddr, &ip_str[0], (socklen_t)sizeof(ip_str));
    printf("%s\n", ip_str);

    memset(&ip_str[0], 0x00, sizeof(ip_str));

    printf("Destination IP : ");
    daddr = (struct in_addr *)&(ip_hdr->daddr);
    inet_ntop(AF_INET, daddr, &ip_str[0], (socklen_t)sizeof(ip_str));
    printf("%s\n", ip_str);

    return;
}

void print_arp_header(const unsigned char *p)
{
    struct arphdr *arp_hdr = (struct arphdr *)(p + sizeof(struct ether_header));
    printf("----ARP Packet Receive----\n");
    print_hardware_type(arp_hdr);
    print_arp_prot(arp_hdr);
    print_arp_operation(arp_hdr);
}

void print_hardware_type(struct arphdr *arp_hdr)
{
    printf("Hardware Type : ");
    if (ntohs(arp_hdr->ar_hrd) == ARPHRD_ETHER)
    {
        printf("Ethernet\n");
    }
    else
    {
        printf("Not Ether\n");
    }
}

void print_arp_prot(struct arphdr *arp_hdr)
{
    printf("Protocol Type : ");
    if (ntohs(arp_hdr->ar_pro) == ETHERTYPE_IP)
    {
        printf("IP\n");
    }
    else
    {
        printf("Not IP\n");
    }
}

void print_arp_operation(struct arphdr *arp_hdr)
{
    printf("Operation : ");
    switch (ntohs(arp_hdr->ar_op))
    {
    case ARPOP_REQUEST:
        printf("ARP REQUEST\n");
        break;
    case ARPOP_REPLY:
        printf("ARP REPLY\n");
        break;
    case ARPOP_RREQUEST:
        printf("ARP REVREQUEST\n");
        break;
    case ARPOP_RREPLY:
        printf("ARP REVREPLY\n");
        break;
    case ARPOP_InREQUEST:
        printf("ARP INVREQUEST\n");
        break;
    case ARPOP_InREPLY:
        printf("ARP INVREPLY\n");
        break;

    default:
        break;
    }
}