/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cFiles/file.h to edit this template
 */

/* 
 * File:   sessions.h
 * Author: smorodin
 *
 * Created on July 15, 2022, 1:31 PM
 */

#ifndef SESSIONS_H
#define SESSIONS_H

#include "stdio.h"
#include <map>
#include <vector>
#include <string>

#include "frame.h"
#include "tools.h"

class SESSION;

void analiz_to_block(SESSION* session);

class SESSION_FRAME {
public:
    DIRECTION direction;
    unsigned int size, payload_size;
    
    void fill(FRAME *frame) {
        direction = frame->direction;
        size = frame->frame_size;
        payload_size = frame->payload_size;
    }
    
    void clean() {
        size = 0;
        payload_size = 0;
        direction = undefined;
    }
    SESSION_FRAME() {};
};

class SESSION {
public:
    SESSION_FRAME frames[10];
    unsigned int size, payload_size, packet_count, packet_with_payload_count;
    unsigned char mac_src[6], mac_dst[6];
    unsigned char ip_proto; 
    unsigned int ipv4_src_ip, ipv4_dst_ip;
    unsigned short ipv4_src_port, ipv4_dst_port;
    DIRECTION direction; // ingress, egress
    bool dhcp_request, dhcp_responce;
    bool dns_request, dns_responce;
    bool is_need_block_complete, is_need_block_show;
    
    std::string dns;
    
    void ssave(FILE *f) {
        //fprintf(f, "", );
    }
    
    void clean() {
        for(int i=0;i<10;i++) {
            frames[i].clean();
        }
        for(int i=0;i<6;i++) {
                mac_src[i] = 0;
                mac_dst[i] = 0;
            }
        is_need_block_complete = false;
        is_need_block_show = false;
        ip_proto = 0;
        ipv4_src_ip = 0; ipv4_dst_ip = 0;
        ipv4_src_port = 0; ipv4_dst_port = 0;
        direction = undefined;
        dhcp_request = false; dhcp_responce = false;
        dns_request = false; dns_responce = false;
        dns = "";
        size = 0;
        payload_size = 0;
        packet_count = 0;
        packet_with_payload_count = 0;
    }
    void add_to_session(FRAME *frame) {
        if(packet_count == 0) {
            for(int i=0;i<6;i++) {
                mac_src[i] = frame->mac_src[i];
                mac_dst[i] = frame->mac_dst[i];
            }
            dns = find_dns(direction == ingress ? ipv4_dst_port : ipv4_src_port);
        }
        
        if(packet_count < 10) frames[packet_count].fill(frame);;
        
        ip_proto = frame->ip_proto;
        ipv4_src_ip = frame->ipv4_src_ip;
        ipv4_dst_ip = frame->ipv4_dst_ip;
        ipv4_src_port = frame->ipv4_src_port;
        ipv4_dst_port = frame->ipv4_dst_port;
        direction = frame->direction;
        dhcp_request = frame->dhcp_request; dhcp_responce = frame->dhcp_responce;
        dns_request = frame->dns_request; dns_responce = frame->dns_responce;
        size += frame->frame_size;
        payload_size += frame->payload_size;
        packet_count++;
        if(frame->payload_size > 0) packet_with_payload_count++;
    
        frame->stored_to_session();
        if(packet_count >= 4 && packet_count <= 10) {
            analiz_to_block(this);
        }
        if(payload_size > 100000) {
            if(frames[2].size == 66) {
                 if(is_need_block_show == false) {
                    is_need_block_show = true;
                    printf(">100000 [%d %d %d   %d %d   %d %d]\n", frames[0].size, frames[1].size, frames[2].size, frames[3].size, frames[4].size, frames[5].size, frames[6].size);
                };
            };
            return;
        }
    }
    SESSION() {
        clean();
    };
};

class SESSIONS {
public:
    std::map<std::string, SESSION> items;
    void add_to_session(FRAME *frame);
    void save();
    SESSIONS();
};

#endif /* SESSIONS_H */

