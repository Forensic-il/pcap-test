#include "libnet.h"

void print_ethrnet(struct_eth *eth);
void print_ip(struct_ip *ip);
void print_tcp(struct_tcp *tcp);
void print_payload(struct_payload *pl);
void print_packet(struct_eth *eth, struct_ip *ip, struct_tcp *tcp, struct_payload *pl);

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_ethrnet(struct_eth *eth){

    printf("\n=========================================");
    printf("\nEthrnet src mac : ");
    for(int i=0; i<ETHER_ADDR_LEN; i++){
        printf("%02x:", eth->ether_shost[i]);
        if (i==5)
            printf("%02x", eth->ether_shost[i]);
    }
    printf("\nEthernet dst mac : ");
    for(int i=0; i<ETHER_ADDR_LEN; i++){
        printf("%02x:", eth->ether_dhost[i]);
        if (i==5)
            printf("%02x", eth->ether_dhost[i]);
    }
}

void print_ip(struct_ip* ip){
    printf("\nIP src : %s", inet_ntoa(ip->ip_src)); // 네트워크 바이트 값을 ip표기 형태로 변환
    printf("\nIP dst : %s", inet_ntoa(ip->ip_dst));
}

void print_tcp(struct_tcp *tcp){
    printf("\nTCP src : %d", ntohs(tcp->th_sport));
    printf("\nTCP dst : %d", ntohs(tcp->th_dport));
}

void print_payload(struct_payload *pl){
    printf("\nPayload data : ");
    for(int i=0; i<8; i++){
        printf("%02x", pl->data[i]);
    }
}
void print_packet(struct_eth *eth, struct_ip *ip, struct_tcp *tcp, struct_payload *pl){
    if(ip->ip_p == 6){
    print_ethrnet(eth);
    print_ip(ip);
    print_tcp(tcp);
    if(pl->data[0] != 0)
        print_payload(pl);
    }
}
int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        struct_eth *eth = (struct_eth*)packet;
        struct_ip *ip = (struct_ip*)(packet+sizeof (struct_eth));
        struct_tcp *tcp = (struct_tcp*)(packet+sizeof (struct_eth)+sizeof (struct_ip));
        struct_payload *pl = (struct_payload*)(packet+sizeof (struct_eth)+sizeof (struct_ip)+sizeof(struct_tcp));
        print_packet(eth,ip,tcp,pl);
    }
	pcap_close(pcap);
}
