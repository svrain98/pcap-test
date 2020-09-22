#include <pcap.h>
#include <stdio.h>
#include<libnet.h>
#include<netinet/in.h>
#include<arpa/inet.h>
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}
void print_MAC(struct libnet_ethernet_hdr* eth){
    printf("Src mac : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
    printf("Dst mac : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
}

void print_IP(struct libnet_ipv4_hdr* ip){
    printf("Src ip : ");
    printf("%s \n",inet_ntoa(ip->ip_src));
    printf("Dst ip : ");
    printf("%s \n",inet_ntoa(ip->ip_dst));
}

void print_PORT(struct libnet_tcp_hdr* tcp){
    printf("Src port : %d\n", ntohs(tcp->th_sport));
    printf("Dst port : %d\n", ntohs(tcp->th_dport));
}
void print_PAYLOAD(const u_char* data,int len)
{
printf("Data: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", data[i]);
    printf("\n");
    printf("-----------------------------------------------------\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
	
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	eth= (struct libnet_ethernet_hdr*)packet;
	ip= (struct libnet_ipv4_hdr*)(packet+14);
	tcp=(struct libnet_tcp_hdr*)(packet+14+ip->ip_hl*4);
	const u_char *data= packet + 14+ ip->ip_hl*4 + tcp->th_off*4;
	
	if(eth->ether_type==0x0008)
		if(ip->ip_p==0x06){
			print_MAC(eth);
			print_IP(ip);
			print_PORT(tcp);
			print_PAYLOAD(data,16);

	}
    }

    pcap_close(handle);
}
