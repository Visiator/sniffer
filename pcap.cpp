/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cppFiles/class.cc to edit this template
 */

/* 
 * File:   PCAP.cpp
 * Author: smorodin
 * 
 * Created on July 8, 2022, 5:11 PM
 */

#include "pcap.h"
#include "sessions.h"
#include "frame.h"

extern FRAME frame;
extern SESSIONS sessions;

void analiz(int frame_no, unsigned char *buf, int buf_size);

PCAP::PCAP() {
}

PCAP::~PCAP() {
}

bool PCAP::read_ui32(FILE *f, unsigned int *hh) {
    unsigned char buf[4], *q;
    int i;
    *hh = 0;
    i = fread(buf, 1, 4, f);
    if(i != 4) {
        return false;
    };
    q = (unsigned char *)hh;
    q[0] = buf[0];
    q[1] = buf[1];
    q[2] = buf[2];
    q[3] = buf[3];
    return true;
}

bool PCAP::write_ui32(FILE *f, unsigned int hh) {
    fwrite(&hh, 1, 4, f);
    return true;
}


bool PCAP::read_page(FILE *f, unsigned int sz) {
    page_size = 0;
    if(page_buff_size < sz) {
        if(page_buff != NULL) delete[] page_buff;
        page_buff_size = sz * 2;
        page_buff = new unsigned char[page_buff_size];
    }
    
    int i;
    i = fread(page_buff, 1, sz, f);
    if(i == sz) {
        page_size = i;
        return true;
    };
    return false;
}

bool PCAP::read_from_page_ui32(unsigned int *idx, unsigned int *val) {
    *val = 0;
    if(*idx+4 > page_size) return false;
    unsigned char *q;
    q = (unsigned char *)val;
    q[0] = page_buff[*idx + 0];
    q[1] = page_buff[*idx + 1];
    q[2] = page_buff[*idx + 2];
    q[3] = page_buff[*idx + 3];
    
    *idx += 4;
    return true;
}

bool PCAP::read_from_page_ui64(unsigned int *idx, unsigned long long *val) {
    *val = 0;
    if(*idx+8 > page_size) return false;
    unsigned char *q;
    q = (unsigned char *)val;
    q[0] = page_buff[*idx + 0];
    q[1] = page_buff[*idx + 1];
    q[2] = page_buff[*idx + 2];
    q[3] = page_buff[*idx + 3];
    q[4] = page_buff[*idx + 4];
    q[5] = page_buff[*idx + 5];
    q[6] = page_buff[*idx + 6];
    q[7] = page_buff[*idx + 7];
    
    *idx += 8;
    return true;
};

bool PCAP::decode_page_0a0d0d0a() {
    bool b;
    unsigned int p1;
    unsigned int i;
    i = 0;
    
    b = read_from_page_ui32(&i, &p1);
    if(p1 != 0x1a2b3c4d) {
        printf("corrupted! 3\n");
        return false;
    }
    
    return true;
}

void PCAP::decode_page_1() {
    
}

void PCAP::decode_page_5() {
    
}

void PCAP::decode_page_6(int frame_no) {
    bool b;
    unsigned int nomer_interface;
    unsigned long long timestamp;
    unsigned int packets_size;
    unsigned int raw_size;
    unsigned int i;
    i = 0;
    
    b = read_from_page_ui32(&i, &nomer_interface);
    b = read_from_page_ui64(&i, &timestamp);
    b = read_from_page_ui32(&i, &packets_size);
    b = read_from_page_ui32(&i, &raw_size);
    if(packets_size != raw_size) {
        printf("PCAP packets_size != raw_size \n");
    }
    if(frame_no == 211) {
        printf("211\n");
        
    }
    //frame.clean();
    analiz(frame_no, page_buff+20, packets_size);
    //sessions.add_to_session(&frame);   
    //sessions.save();
    
}

void save_pcap() {
    FILE *f;
    f = fopen("t.pcapng", "wb");
    if(f == NULL) return;
    
}

void PCAP::load_from_file(char *name_file) {
    FILE *f;
    
    //w = fopen("wwww.pcap", "wb");
    
    
    f = fopen(name_file, "rb");
    if(f == NULL) return;
    unsigned int hh, pp, ss;
    bool b;
    int frame_no = 1;
    do
    {
    
        b = read_ui32(f, &hh);
        if(b == false) {
            break;
        }
        b = read_ui32(f, &ss);

        b = read_page(f, ss-12);

        //write_ui32(w, hh);
        //write_ui32(w, ss);
        //fwrite(page_buff, 1, ss-12, w);
        //write_ui32(w, ss);
        
        
        if(hh == 0x0a0d0d0a) {
            decode_page_0a0d0d0a();
        } else {
          if(hh == 1) {
            decode_page_1();
            //fclose(w);
          } else {
            if(hh == 6) {
              decode_page_6(frame_no++);
            } else {
                if(hh == 5) {
                    decode_page_5();
                } else {
                    if(hh == 4) { // NRB
                        
                    } else {
                        printf("corrupted! 1\n");
                        break;
                    };
                };
            } 
          }   
        }
        
        b = read_ui32(f, &pp);
        if(ss != pp) {
            printf("corrupted! 2\n");
            break;
        }
        
        
        
    } while(true);
    fclose(f);
}
