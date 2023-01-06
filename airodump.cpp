#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string.h>
#include "mac.h"
#include <map>

using namespace std;

struct ieee80211_radiotap_header {
    u_char it_version;
    u_char it_pad;
    u_int16_t it_len;
	u_char it_present_flags[12];
	u_char flags;
	u_char dataRate;
	u_int16_t ch_frequency;
	u_int16_t ch_flags;
	u_char antenna_signal;	
};

struct ieee80211_beacon_frame{
	u_int16_t frameCtl;
	u_int16_t duration;
	Mac dstAddr;
	Mac srcArrr;
	Mac bssId;
};

struct ieee80211_wireless_management{
	u_int64_t timestamp;
	u_int16_t beaconInterval;
	u_int16_t capablityInfo;
	u_int8_t tagNumber;
	u_int8_t tagLength;
	unsigned char SSID[33];
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
		struct ieee80211_wireless_management *wireless_mgr = (struct ieee80211_wireless_management *)(packet + radiotap->it_len + 24);

		//Beacon 프레임인지 Type 확인
		if(ntohs(beaconframe->frameCtl) != 0x8000){
			printf("It's Not Beacon Frame\n");
		    continue; 
		}

		if(wireless_mgr->tagNumber != 0){
			printf("tagNumber 0\n");
		    continue; 
		}
		else{
			bool twodotfour = (radiotap->ch_flags & 0x0080);
			int ch = -1;
			if(twodotfour){
				ch = ((radiotap->ch_frequency - 2412) / 5) + 1;
			}
			wireless_mgr->SSID[wireless_mgr->tagLength] = '\0';
			printf("BSSID : %s, SSID : %s, frequency : %dMhz, type : %s, ch : %d\n", string(beaconframe->srcArrr).c_str(), wireless_mgr->SSID, radiotap->ch_frequency, (twodotfour) ? "2.4GHz" : "5GHz", ch);
		}
			
	}

	pcap_close(pcap);
}
