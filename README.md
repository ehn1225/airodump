<h1>airodump</h1>
무선 네트워크 패킷을 캡쳐하여 Beacon 프레임에서 BSSID, SSID, ch 등을 파싱하여 출력하는 프로그램입니다.<br>

syntax: airodump [interface] <br>
sample: airodump wlan0

<h1>pcap 파일로 테스트 하는 방법</h1>
<h2>1. 더미 무선 인터페이스 추가</h2>
sudo modprobe mac80211_hwsim radios=1<br>
<h2>인터페이스 목록 확인 방법</h2>
iw dev <br>
iwconfig
<h2>tcpreplay로 더미 인터페이스에 패킷 전송</h2>
sudo tcpreplay -i wlan1 sample.pcap <br>

