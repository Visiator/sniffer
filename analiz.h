/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cFiles/file.h to edit this template
 */

/* 
 * File:   analiz.h
 * Author: smorodin
 *
 * Created on July 15, 2022, 11:41 AM
 */

#ifndef ANALIZ_H
#define ANALIZ_H

#include "frame.h"
#include "tools.h"

/*
struct EthernetII
{
public:
    unsigned char mac_dst[6];
    unsigned char mac_src[6];
    unsigned short type;
    void set_endian() {
       unsigned char cc, *q;
       q = (unsigned char *)&type;
       cc = q[0];
       q[0] = q[1];
       q[1] = cc;
       
    }
};*/

void analiz_ipv4_udp_payload(unsigned char *buf, int buf_size, FRAME *frame);
void analiz_ipv4_udp(unsigned char *buf, int buf_size, FRAME *frame);
void analiz_ipv4_tcp(unsigned char *buf, int buf_size, FRAME *frame);
void analiz_ipv4(int frame_no, unsigned char *buf, int buf_size, FRAME *frame);
void analiz(int frame_no, unsigned char *buf, int buf_size);

void analiz_r0(int frame_no, unsigned char *buf, int buf_size);

#endif /* ANALIZ_H */

