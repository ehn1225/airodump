//20230106 Best of the Best 11th 이예찬
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
	u_int32_t it_present_flags;
};

struct ieee80211_radiotap_channel {
	u_int16_t ch_frequency;
	u_int16_t ch_flags;
	int8_t antenna_signal;	
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
	unsigned char SSID[33]; //MAX length 32
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

int Calc_ch(int frequency){
	if(frequency >= 2412 && frequency <= 2484){	
		if (frequency == 2484)
			return (frequency-2412) /5;
		return (frequency-2412) /5 + 1;
	}
	else if( frequency >= 5170 && frequency <= 5825)
		return (frequency-5170) /5 + 34;
	else 
		return -1;
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

	map<unsigned int, int> beacons;

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
			//printf("It's Not Beacon Frame\n");
		    continue; 
		}
		//SSID를 가지는지 확인
		if(wireless_mgr->tagNumber != 0){
		    continue; 
		}
		else{
			//Channel frequency Offset from packet[0]
			unsigned short ch_offset = 4;
			u_int32_t present_flags = radiotap->it_present_flags;

			bool TSFT = false;
			//MAC timestamp flag
			if(TSFT = (present_flags & 0x00000001))
				ch_offset += 8;

			//Flags flag
			if(present_flags & 0x00000002)
				ch_offset += 1;

			//Data Rate flag
			if(present_flags & 0x00000004)
				ch_offset += 1;

			//Channel flag
			if(!(present_flags & 0x00000008))
				printf("No Channel?");	
			
			//Handling Extended Presence masks
			int count = 1;
			while(present_flags & 0x80000000){
				memcpy((char*)&present_flags, packet + 4 * (count + 1), 4);
				count++;
			}
			ch_offset += (4 * count);

			//Alignment in Radiotap
			if(count == 2 && TSFT)
				ch_offset += 4;

			//Channel 정보 파싱
			struct ieee80211_radiotap_channel *radiotap_ch = (struct ieee80211_radiotap_channel *)(packet + ch_offset);
			
			//2.4GHz or 5Ghz 확인
			bool twodotfour = (radiotap_ch->ch_flags & 0x0080);

			//AP와 주파수 대역을 구분하여 Beacon을 카운트하기 위해
			//BSSID MAC 뒷 4바이트를 이용해 id 생성
			unsigned int id;
			uint8_t* mac(beaconframe->bssId);
			memcpy((char*)&id, (char*)mac + 2, 4);
			//5GHz 대역일 경우 2.4 GHz 대역과 구분하기 위해 +1 수행
			(!twodotfour) ? id++ : id;

			//std::map 자료구조를 이용하여 beacon 카운트
			if(beacons.find(id) != beacons.end())
				beacons[id] += 1;
			else
				beacons[id] = 1;

			//char array SSID를 %s 로 출력하기 위해 널스트링 추가
			wireless_mgr->SSID[wireless_mgr->tagLength] = '\0';

			//화면 출력
			printf("BSSID : %s, ch : %d (%dMHz, %s), PWR : %d, Beacon : %d, SSID : %s\n", string(beaconframe->srcArrr).c_str(),Calc_ch(radiotap_ch->ch_frequency), radiotap_ch->ch_frequency, (twodotfour) ? "2.4GHz" : "5GHz", radiotap_ch->antenna_signal, beacons[id], wireless_mgr->SSID);
		}
	}

	pcap_close(pcap);
}
