#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string.h>
#include "mac.h"

using namespace std;

struct ieee80211_radiotap_header {
    u_char it_version;     /* set to 0 */
    u_char it_pad;
    u_int16_t it_len;         /* entire length */
	u_char it_present[4];     /* fields present */
};

struct ieee80211_beacon_frame{
	u_int16_t frameCtl;
	u_int16_t duration;
	Mac dstAddr;
	Mac srcArrr;
	Mac bssId;
};

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump wlan0\n");
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
		const unsigned char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		//802.11 Radiotap에서 Radiotap 해더의 길이를 가져오고, 이를 통해 다음 레이어로 넘어감
		struct ieee80211_radiotap_header *radiotap = (struct ieee80211_radiotap_header *)packet;
		struct ieee80211_beacon_frame *beaconframe = (struct ieee80211_beacon_frame *)(packet + radiotap->it_len);

		//Beacon 프레임인지 Type 확인
		if(ntohs(beaconframe->frameCtl) != 0x8000){
			printf("It's Not Beacon Frame\n");
		    continue; 
		}

		printf("SA : %s, BSSID : %s\n", string(beaconframe->srcArrr).c_str(), string(beaconframe->bssId).c_str());
		//cout << string(beaconframe->dstAddr) << endl;
		// struct ip *ip_hdr = (struct ip *)(packet+SIZE_ETHERNET); //IP Header Struct
		// //if next layer is not tcp, move next packet
		// if(ip_hdr->ip_p != 0x06){
		// 	printf("This Packet is not TCP  ptotocol\n");
		//        	continue;
		// }
		// u_int size_ip;
		// u_int size_tcp;
		// size_ip = IP_HL(ip_hdr)*4;
		// struct tcp *tcp_hdr = (struct tcp*)(packet + SIZE_ETHERNET + size_ip); //TCP Header Struct
		// size_tcp = TH_OFF(tcp_hdr)*4; 
		
		// printf("================ Ethernet ================\n");
		// printf("Source MAC Address     : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0],eth_hdr->ether_shost[1],eth_hdr->ether_shost[2],eth_hdr->ether_shost[3],eth_hdr->ether_shost[4],eth_hdr->ether_shost[5]);
		// printf("Dstination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0],eth_hdr->ether_dhost[1],eth_hdr->ether_dhost[2],eth_hdr->ether_dhost[3],eth_hdr->ether_dhost[4],eth_hdr->ether_dhost[5]);

		// printf("=================== IP ===================\n");
		// printf("Source IP Address     : %s\n", inet_ntoa(ip_hdr->ip_src));
		// printf("Destnation IP Address : %s\n", inet_ntoa(ip_hdr->ip_dst));

		// printf("================== TCP ===================\n");
        // 	printf("Source Port     : %d\n", ntohs(tcp_hdr->th_sport));
        // 	printf("Destnation Port : %d\n", ntohs(tcp_hdr->th_dport));
		// const u_char * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		// u_int payload_size = ntohs(ip_hdr->ip_len) - size_ip - size_tcp;
		// if(payload_size > 10){payload_size = 10;}
		// if(payload_size == 0){
		// 	printf("No Data");
		// }
		// else{
		// 	for(int i =0; i < payload_size;i++){
		// 		printf("%02x ", payload[i]);
		// 	}	
		
		
		// }
		// printf("\n============= End Of Packet ==============\n\n\n");

			
	}

	pcap_close(pcap);
}
