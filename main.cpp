#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

typedef struct pcap_eth {
    u_char eth_dmac [ETHER_ADDR_LEN];
    u_char eth_smac [ETHER_ADDR_LEN];
    u_int16_t eth_type;
};

typedef struct pcap_ip {
    u_char ip_verlen;
    //u_char ip_len : 4;
    u_char ip_tos;
    u_short ip_tleng;
    u_short ip_id;
    u_short ip_flag;
#define IP_xF 0x8000;
#define IP_DF 0x4000;
#define IP_MF 0x2000;
#define IP_OFFMASK 0x1fff;
    u_char ip_ttl;
    u_char ip_prot;
    u_short ip_check;
    u_int8_t ip_src[4];
    u_int8_t ip_dst[4];
    //struct in_addr ip_src,ip_dst;
};

#define IP_HL(ip)       (((ip)->ip_ver) & 0x0f)
#define IP_V(ip)       (((ip)->ip_ver) >> 4)

typedef u_int32_t tcp_seq;

typedef struct pcap_tcp {
    u_int8_t tcp_sport[2];
    u_int8_t tcp_dport[2];
    tcp_seq tcp_sn;
    tcp_seq tcp_ak;
    u_int8_t tcp_offx2;
#define TCP_OFF(tcp)	(((tcp)->tcp_offx2 & 0xf0) >> 4)
    u_int8_t tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
    u_int16_t tcp_win;
    u_int16_t tcp_check;
    u_int16_t tcp_urp;
};

typedef struct tcp_data {
    u_int8_t Data[10];
};

u_int16_t my_ntohs(u_int16_t n) {
    return n >> 8 | n << 8;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(u_char *mac){
    for(int i = 0;i <6; i++){
        printf("%02x",mac[i]);
        if(i!=5){
            putchar(':');
        }
    }
    putchar('\n');
}

void print_ip(u_int8_t *ip){
    for(int i = 0;i <4; i++){
        printf("%d", ip[i]);
        if(i!=3){
            putchar('.');
        }
    }
    putchar('\n');
}

void print_port(u_int8_t *port){
    printf("%d",port[0]<<8 | port[1]);
    putchar('\n');
}

void print_data(u_int8_t *data, u_int16_t total_len, u_int8_t iphdr_len, u_int8_t tcphdr_len) {
    total_len = (total_len << 8 | total_len >> 8);
    total_len -= iphdr_len+tcphdr_len;
    printf("TCP Data Length : %d\n", total_len);
    if (total_len != 0) {
        for(int i=0; i<10; i++){
            printf(" %02x ",data[i]);
            if(i!=9){
                putchar(':');
            }
        }
        putchar('\n');
    }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct pcap_eth *eth;
    struct pcap_ip *ip;
    struct pcap_tcp *tcp;
    struct tcp_data *data;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    eth = (struct pcap_eth*)packet;
    printf("Source MAC : ");
    print_mac(eth->eth_smac);
    printf("Destination MAC : ");
    print_mac(eth->eth_dmac);
    //printf("%04x\n", my_ntohs(eth->eth_type));
    //printf("%d\n", ip->ip_prot);
    if(eth->eth_type == my_ntohs(0x0800)) {
        ip = (struct pcap_ip*)(packet+14);
        printf("Source IP : ");
        print_ip(ip->ip_src);
        printf("Destination IP : ");
        print_ip(ip->ip_dst);

        u_int8_t ip_length = (ip->ip_verlen&0x0f)*4;
        if(ip->ip_prot == 0x06){
            tcp = (struct pcap_tcp*)(packet+14+ip_length);
            printf("Source Port : ");
            print_port(tcp->tcp_sport);
            printf("Destination Port : ");
            print_port(tcp->tcp_dport);
            u_int8_t tcp_leng = (tcp->tcp_offx2+tcp->tcp_flags>>4)*4;
            data = (struct tcp_data*)(packet+14+ip_length+tcp_leng);
            print_data(data->Data, ip->ip_tleng, ip_length, tcp_leng);
        }
    }
  }

  pcap_close(handle);
  return 0;
}
