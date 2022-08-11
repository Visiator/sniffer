/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cFiles/file.h to edit this template
 */

/* 
 * File:   pcap.h
 * Author: smorodin
 *
 * Created on July 15, 2022, 6:27 PM
 */

#ifndef PCAP_H
#define PCAP_H

#include <stdio.h>
#include <string.h>

class PCAP {
public:
    unsigned char *page_buff =  NULL;
    int page_buff_size = 0;
    int page_size = 0;
    bool read_page(FILE *f, unsigned int sz);
    bool read_ui32(FILE *f, unsigned int *hh);
    bool write_ui32(FILE *f, unsigned int hh);
    void load_from_file(char *name_file);
    
    bool decode_page_0a0d0d0a();
    void decode_page_1();
    void decode_page_5();
    void decode_page_6(int frame_no);
    
    bool read_from_page_ui32(unsigned int *idx, unsigned int *val);
    bool read_from_page_ui64(unsigned int *idx, unsigned long long *val);
    
    PCAP();
    virtual ~PCAP();
private:

};

#endif /* PCAP_H */

