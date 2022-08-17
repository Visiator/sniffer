/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cppFiles/main.cc to edit this template
 */

/* 
 * File:   main.cpp
 * Author: smorodin
 *
 * Created on July 15, 2022, 10:18 AM
 */
#include <stdio.h>
#include <cstdlib>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/socket.h>
#include <linux/ioctl.h>
#include <linux/if.h>
//#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <sys/ioctl.h>
//#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <ifaddrs.h>  

#include <string.h>
#include <map>

#include "sessions.h"
#include "analiz.h"
#include "frame.h"
#include "pcap.h"
#include "fragments_queue.h"
#include "tools.h"

std::map<unsigned int, std::string> global_dns_list;
//FRAME frame;
SESSIONS sessions;
PCAP pcap;
FRAGMENTS_QUEUE queue;

void analiz_TZSP(int frame_no, unsigned char *buf, int sz) {
    
    unsigned char header_ver, header_type;
    unsigned short header_proto;
    int i = 0;
    header_ver = buf[i++];
    header_type = buf[i++];
    header_proto = get_i16(buf[i++], buf[i++]);
    if(header_ver != 1) {
        wtf("analiz_TZSP header_ver != 1", frame_no, buf, sz);
        return;
    }

    unsigned char tag, len;
    tag = buf[i++];
    while( tag != 1 ) {
        len = buf[i++];
        i += len;
        if(i > sz) {
            printf("wtf sz analiz_TZSP\n");
            return;
        }
        tag = buf[i++];
    }
    //frame.clean();
    analiz(frame_no, buf+i, sz-i);
    //sessions.add_to_session(&frame);   
    //sessions.save();
}


void mikrotik(unsigned int mport) {
    int handle = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    if ( handle <= 0 ) { printf( "failed to create socket\n" ); return; }

    sockaddr_in address{};  
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( (unsigned short) mport ); // 37008
    if ( bind( handle, (const sockaddr*) &address, sizeof(sockaddr_in) ) < 0 ) { printf( "failed to bind socket\n" ); return; }

    unsigned char packet_data[2000];
    int maximum_packet_size = 2000;
    
    sockaddr_in from;
    unsigned int fromLength = sizeof( from );
    unsigned int from_address;
    unsigned int from_port;
    
    int frame_no = 1;
    
    while ( true )
    {

        int received_bytes = recvfrom( handle, (char*)packet_data, maximum_packet_size, 0, (sockaddr*)&from, &fromLength );

        if ( received_bytes <= 0 )
        break;

        from_address = ntohl( from.sin_addr.s_addr );
        from_port = ntohs( from.sin_port );

        if(received_bytes > 0) {
            printf("M - %d\n", received_bytes);
            analiz_TZSP(frame_no++, packet_data, received_bytes);
        };
        
    }
}



void load_from_picap(std::string filename) {
    
    pcap.load_from_file((char *)filename.c_str());
}

//****************************************************************************//


int getsock_recv(int index) {
    int sd; // дескриптор сокета
/*
 * При работе с пакетными сокетами для хранения адресной информации
 * сетевого интерфейса вместо структуры sockaddr_in используется структура
 * sockaddr_ll (см. <linux/if_packet.h>)
 */
    struct sockaddr_ll s_ll;

/*
 * Cоздаем пакетный сокет. Т.к. MAC-адреса мы тоже собираемся обрабатывать,
 * параметр type системного вызова socket принимает значение SOCK_RAW
 */
    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sd < 0) return -1;

    memset((void *)&s_ll, 0, sizeof(struct sockaddr_ll));

/*
 * Заполним поля адресной структуры s_ll
 */
    s_ll.sll_family = PF_PACKET; // тип сокета
    s_ll.sll_protocol = htons(ETH_P_ALL); // тип принимаемого протокола
    s_ll.sll_ifindex = index; // индекс сетевого интерфейса

/*
 * Привязываем сокет к сетевому интерфейсу. В принципе, делать это не
 * обязательно, если на хосте активен только один сетевой интерфейс.
 * При наличии двух и более сетевых плат пакеты будут приниматься сразу со всех
 * активных интерфейсов, и если нас интересуют пакеты только из одного сегмента
 * сети, целесообразно выполнить привязку сокета к нужному интерфейсу
 */
    if(bind(sd, (struct sockaddr *)&s_ll, sizeof(struct sockaddr_ll)) < 0) {
	close(sd);
        printf("err\n");
	return -1;
    }

    return sd;
}
 __u8 buff[2000];
void start_sniff(int eth_idx) {

    __u32 num = 0;
    int i, eth0_if, rec = 0, ihl = 0;
    struct iphdr ip; // структура для хранения IP заголовка пакета
    struct tcphdr tcp; // TCP заголовок
    struct ethhdr eth; // заголовок Ethernet-кадра
    static struct sigaction act;
    
    if((eth0_if = getsock_recv(eth_idx)) < 0) {
	perror("e) getsock_recv");
	return;
    }

    
    struct ifreq req;
    strcpy(req.ifr_name, "enx00e04c3601ad");
    ioctl (eth0_if, SIOCGIFMTU, &req);
    int mtu = req.ifr_mtu;


    printf("mtu = %d\n", mtu);

FILE *f;
    
    int frame_no = 1;
    i = 0;
    while(true) {
        
        //printf("i = %d", i);
	memset(buff, 0, 2000);
	
	rec = recvfrom(eth0_if, (char *)buff, mtu + 18, 0, NULL, NULL);
        printf("%d\n", rec);
	if(rec < 0 || rec > ETH_FRAME_LEN+4) {
	    perror("a) recvfrom");
            printf("rec=%d - %d\n", rec, ETH_FRAME_LEN);
	    return;
	}

        char ss[500];
        
        /*sprintf(ss, "dump_%d.txt", i);
        f = fopen(ss, "wb");
        if(f != NULL) {
            fwrite(buff, 1, rec, f);
            fclose(f);
        }*/
        
        //analiz(buff, rec);
        //frame.clean();
        /// analiz(frame_no++, buff, rec);
        analiz(frame_no++, buff, rec);
        
        
        
        i++;
    }
    printf("END\n");
    return;
    
}

/*void f_to_hex() {
    FILE *f;
    f = fopen("tmpl.pcapng", "rb");
    if(f != NULL) {
        int j = 0, i = fgetc(f);
        while(i != EOF) {
            printf("0x%02x, ", i);
            j++;
            if(j >= 20) {
                printf("\n");
                j = 0;
            }
            i = fgetc(f);
        }
        fclose(f);
    }
    printf("\n");
}*/

int main(int argc, char** argv) {


    
    unsigned int mport = 37008;
    
    std::string param1, param2;
    
    if(argc >= 2) param1 = std::string(argv[1]);
    if(argc >= 3) param2 = std::string(argv[1]);
    
    char fn[] = {"/var/www/html/sniffer_web/need_block"};
    if(!DirectoryExists(fn)) {
        mkdir(fn, 0777);
        chmod(fn, 0777);
    }
    
    
    
    if(param1 != "" && param2 == "") {

        int x;
        x = to_integer( param1.c_str() );
        
        if(x > 0) {
            start_sniff(x);
            return 0;
        }

        if(file_exists(param1)) {
            printf("load from picap...\n");
            load_from_picap(param1);
            
            return 0;
        }
    }
    
    if(param1 == "mikrotik") 
    {
        printf("mikrotik...\n");
        mikrotik(mport);;
        return 0;
    }
    
    return 0;
}

