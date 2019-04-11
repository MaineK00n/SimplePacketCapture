#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "capture.h"

int main(int argc, char *argv[])
{
    pcap_t *pd = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];

    if (argc < 2)
    {
        perror("you do not select NIC!");
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
    printf("receive packet\n");

    char dmac[18] = {0};
    char smac[18] = {0};
    struct ether_header *eth_hdr = (struct ether_header *)p;

    printf("ether header\n");
    printf("dest mac %s\n", convmac_tostr(eth_hdr->ether_dhost, dmac, sizeof(dmac)));
    printf("src mac %s\n", convmac_tostr(eth_hdr->ether_shost, smac, sizeof(smac)));
    printf("ether type %x\n\n", ntohs(eth_hdr->ether_type));

    struct iphdr *ip_hdr = NULL;
    if (ETHERTYPE_IP != ntohs(eth_hdr->ether_type))
    {
        return;
    }
    ip_hdr = (struct iphdr *)(p + sizeof(struct ether_header));
    printf("IP Packet Receive\n");

    show_ipver(ip_hdr);
    show_hdrlen(ip_hdr);
    show_dscp(ip_hdr);
    show_totlen(ip_hdr);
    show_id(ip_hdr);
    show_flag(ip_hdr);
    show_ttl(ip_hdr);
    show_prot(ip_hdr);
    // ip_checksum(ip_hdr);
    show_ipaddr(ip_hdr);

    return;
}

char *convmac_tostr(unsigned char *hwaddr, char *mac, size_t size)
{
    snprintf(mac, size, "%02x:%02x:%02x:%02x:%02x:%02x:", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return mac;
}

void show_ipver(struct iphdr *ip_hdr)
{
    printf("Version: ");
    if (DPCP_IPV4_PKT == ip_hdr->version)
    {
        printf("ipv4\n");
    }
    else if (DPCP_IPV6_PKT == ip_hdr->version)
    {
        printf("ipv6\n");
    }
    else
    {
        printf("unknown version\n");
    }
}

void show_hdrlen(struct iphdr *ip_hdr)
{
    printf("ip header length: %u byte\n", ip_hdr->ihl * 4);
}

void show_ipprd(struct iphdr *ip_hdr)
{
    printf("ip precedence: ");
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

void show_dscp(struct iphdr *ip_hdr)
{
    int dscp = IPTOS_DSCP(ip_hdr->tos);
    printf("differentiated services code point\n");
    printf("----\n");

    if (0 != dscp)
    {
        if (0 == IPTOS_CLASS(dscp))
        {
            show_ipprd(ip_hdr);
        }
        else if (IPTOS_DSCP_EF == dscp)
        {
            printf("expendited forwarding: true");
        }
        else
        {
            printf("assured forwarding : ");
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
}

void show_totlen(struct iphdr *ip_hdr)
{
    printf("total length : %u byte\n", ntohs(ip_hdr->tot_len));
}

void show_id(struct iphdr *ip_hdr)
{
    printf("identification : %u byte\n", ntohs(ip_hdr->id));
}

void show_flag(struct iphdr *ip_hdr)
{
    int flag = ntohs(ip_hdr->frag_off);
    printf("flag : ");
    if (IP_DF == ip_hdr->frag_off)
    {
        printf("don't fragment\n");
    }
    else if (IP_MF == ip_hdr->frag_off)
    {
        printf("more fragment\n");
    }
    else
    {
        printf("finish fragment\n");
    }

    printf("flagment offset : %u byte\n", (IP_OFFMASK & flag * 8));
}

void show_ttl(struct iphdr *ip_hdr)
{
    printf("time to live : %u\n", ip_hdr->ttl);
}

void show_prot(struct iphdr *ip_hdr)
{
    printf("protocol : ");
    if (DPCP_PROT_ICMP == ip_hdr->protocol)
    {
        printf("icmp\n");
    }
    else if (DPCP_PROT_TCP == ip_hdr->protocol)
    {
        printf("tcp\n");
    }
    else if (DPCP_PROT_UDP == ip_hdr->protocol)
    {
        printf("udp\n");
    }
    else
    {
        printf("0x%x\n", ip_hdr->protocol);
    }
}

int ip_checksum(struct iphdr *ip_hdr)
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

void show_ipaddr(struct iphdr *ip_hdr)
{
    char ip_str[18] = {0};
    struct in_addr *saddr = NULL;
    struct in_addr *daddr = NULL;

    printf("source ip : ");
    saddr = (struct in_addr *)&(ip_hdr->saddr);
    inet_ntop(AF_INET, saddr, &ip_str[0], (socklen_t)sizeof(ip_str));
    printf("%s\n", ip_str);

    memset(&ip_str[0], 0x00, sizeof(ip_str));

    printf("destination ip : ");
    daddr = (struct in_addr *)&(ip_hdr->daddr);
    inet_ntop(AF_INET, daddr, &ip_str[0], (socklen_t) sizeof(ip_str));
    printf("%s\n", ip_str);

    return;
}