#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

/* sniff_improved.c */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* sniff_improved.c */
struct ipheader {
    unsigned char      iph_ihl:4,
                       iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

/* myheader.h */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    /* Ethernet Header 위치 == packet 포인터의 시작 위치 */
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800)
        return;

    /* IP Header : Ethernet Header(14바이트) 뒤 */
    struct ipheader *ip = (struct ipheader *)
                          (packet + sizeof(struct ethheader));

    /* IP Header Len = iph_ihl * 4byte */
    int ip_header_len = ip->iph_ihl * 4;

    /* TCP만 확인(UDP 무시) */
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    /* TCP Header : IP Header 뒤 */
    struct tcpheader *tcp = (struct tcpheader *)
                            (packet + sizeof(struct ethheader) + ip_header_len);

    /* TCP Header Len = data offset * 4byte */
    int tcp_header_len = TH_OFF(tcp) * 4;

    /* HTTP Payload 길이 = IP전체길이 - IP헤더 - TCP헤더 */
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    /* HTTP Message 시작 위치 = Ethernet + IP Header + TCP Header */
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;

    printf("==========================================================\n");

    /* 출력 Ethernet Header: src/dst MAC */
    printf("[Ethernet Header]\n");
    printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    /* 출력 IP Header: src/dst ip */
    printf("[IP Header]\n");
    printf("  Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    /* 출력 TCP Header: src/dst port */
    printf("[TCP Header]\n");
    printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

    /* 출력 HTTP Message : 전달하려는 내용 */
    if (payload_len > 0) {
        printf("[HTTP Message]\n  ");
        int print_len = (payload_len > 512) ? 512 : payload_len;
        for (int i = 0; i < print_len; i++) {
            if (payload[i] >= 32 && payload[i] <= 126)
                printf("%c", payload[i]);
            else if (payload[i] == '\n')
                printf("\n  ");
            else if (payload[i] != '\r')
                printf(".");
        }
        printf("\n");
    }
    printf("==========================================================\n\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // udp는 무시하고, tcp만 살펴봄.
    bpf_u_int32 net;

    printf("[*] Sniffing on: ens33\n");
    printf("[*] Filter: TCP only\n");
    printf("[*] Ctrl+C to stop.\n\n");

    /* VM 인터페이스 ens33로 변경 */
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    /* 패킷 캡처 반복(got_packet 호출) */
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
