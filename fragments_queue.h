/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cFiles/file.h to edit this template
 */

/* 
 * File:   fragments_queue.h
 * Author: smorodin
 *
 * Created on July 16, 2022, 11:13 AM
 */

#ifndef FRAGMENTS_QUEUE_H
#define FRAGMENTS_QUEUE_H

#include "frame.h"
#include "tools.h"

class IPV4_QUEUE_ITEM
{
public:
    
    unsigned char proto;
    unsigned int src, dst;
    unsigned short id;
    unsigned short *buf;
    unsigned char *cbuf;
    int buf_max_size;
    unsigned int all_data_size;
    unsigned char *get_buf(int sz) {
        if(sz < 0 || sz > buf_max_size) return nullptr;
        if(cbuf == nullptr) cbuf = new unsigned char[buf_max_size];
        int i = 0;
        while(i<sz) {
            cbuf[i] = (unsigned char)buf[i];
            i++;
        }
        return cbuf;
    }
    bool compare(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id) {
        if(proto == ip_proto && src == ip_src && dst == ip_dst && id == ip_id) return true;
        return false;
    }
    bool is_empty() {
        if(proto == 0 && src == 0 && dst == 0 && id == 0) return true;
        return false;
    }
    
    void first_set(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id) {
        proto = ip_proto;
        src = ip_src;
        dst = ip_dst;
        id = ip_id;
        if(buf == nullptr) buf = new unsigned short[buf_max_size];
        for(int i=0;i<buf_max_size;i++) buf[i] = 0xffff;
        
    }
    void add_fragment(unsigned char *buf_, int buf_size, int offset) {
        if(offset < 0 || offset >= buf_max_size) return;
        if(buf_size < 0 || buf_size >= buf_max_size) return;
        if(offset + buf_size >= buf_max_size) return;
        int i;
        i = 0;
        while(i<buf_size) {
            if(buf[i+offset] != 0xffff) {
                wtf("add_fragment");
                return;
            }
            buf[i+offset] = buf_[i];
            i++;
        }
        all_data_size += buf_size;
    }
    bool check_compleet(int sz) {
        if(sz >= buf_max_size) return false;
        int i;
        i = 0;
        while(i < sz) {
            if(buf[i] == 0xffff) return false;
            i++;
        }
        return true;
    }
    void clean() {
        proto = 0;
        src = 0;
        dst = 0;
        id = 0;
        if(buf != nullptr) {
            delete[] buf;
            buf = nullptr;
        }
        all_data_size = 0;
    }
    
    IPV4_QUEUE_ITEM() {
        buf = nullptr;
        cbuf = nullptr;
        buf_max_size = 20000;
        clean();
    }
};

class TCP_QUEUE_ITEM
{
public:
    unsigned int src_ip, dst_ip;
    unsigned short src_port, dst_port;
    unsigned int seq_first, ack_first;
    unsigned int seq_old, ack_old;
    unsigned short *buf;
    unsigned char *cbuf;
    int buf_max_size;
    DIRECTION direction;
    unsigned int all_data_size;
    unsigned char *get_buf(int sz) {
        if(sz < 0 || sz > buf_max_size) return nullptr;
        if(cbuf == nullptr) cbuf = new unsigned char[buf_max_size];
        int i = 0;
        while(i<sz) {
            cbuf[i] = (unsigned char)buf[i];
            i++;
        }
        return cbuf;
    }
    bool compare(DIRECTION direction_, unsigned int ip_src, unsigned short src_port_, unsigned int ip_dst, unsigned short dst_port_) {
        if(direction == direction_ && src_ip == ip_src && dst_ip == ip_dst && src_port == src_port_ && dst_port == dst_port_) return true;
        return false;
    }
    bool is_empty() {
        if(src_ip == 0 && dst_ip == 0 && src_port == 0 && dst_port == 0) return true;
        return false;
    }
    void first_set(DIRECTION direction_, unsigned int src_ip_, unsigned short src_port_, unsigned int dst_ip_, unsigned short dst_port_, unsigned int seq_, unsigned int ack_) {
        direction = direction_;
        src_ip = src_ip_;
        dst_ip = dst_ip_;
        src_port = src_port_;
        dst_port = dst_port_;
        seq_first = seq_;
        ack_first = ack_;
        seq_old = seq_;
        ack_old = ack_;
        if(buf == nullptr) buf = new unsigned short[buf_max_size];
        for(int i=0;i<buf_max_size;i++) buf[i] = 0xffff;
        
    }
    void add_fragment(unsigned char *buf_, int buf_size, int offset) {
        if(offset < 0 || offset >= buf_max_size) return;
        if(buf_size < 0 || buf_size >= buf_max_size) return;
        if(offset + buf_size >= buf_max_size) return;
        all_data_size += buf_size;
        int i;
        i = 0;
        while(i<buf_size) {
            if(buf[i+offset] != 0xffff) {
                wtf("add_fragment(2)");
                return;
            }
            buf[i+offset] = buf_[i];
            i++;
        }
        
    }
    bool check_compleet(int sz) {
        if(sz >= buf_max_size) return false;
        if(sz != all_data_size) return false;
        int i;
        i = 0;
        while(i < sz) {
            if(buf[i] == 0xffff) return false;
            i++;
        }
        return true;
    }
    void clean() {
        direction = undefined;
        src_ip = 0;
        dst_ip = 0;
        src_port = 0;
        dst_port = 0;
        seq_first = 0;
        ack_first = 0;
        seq_old = 0;
        ack_old = 0;
        all_data_size = 0;
        if(buf != nullptr) {
            delete[] buf;
            buf = nullptr;
        }
    }
    
    TCP_QUEUE_ITEM() {
        buf = nullptr;
        cbuf = nullptr;
        buf_max_size = 40000;
        clean();
    }
};

class FRAGMENTS_QUEUE
{
public:
    int current_ipv4_items_count;
    
    IPV4_QUEUE_ITEM ipv4_item[2000]; 
    int ipv4_item_max_count;
    
    TCP_QUEUE_ITEM tcp_item[2000]; 
    int tcp_item_max_count;
    
    
    IPV4_QUEUE_ITEM* find_ipv4_queue(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id);
    IPV4_QUEUE_ITEM* new_ipv4_queue(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id);
    IPV4_QUEUE_ITEM* add_to_ipv4_queue(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id, unsigned short fragment_offset, unsigned char *buf, int buf_size);
    
    TCP_QUEUE_ITEM* find_tcp_queue(DIRECTION direction, unsigned int src_ip_, unsigned short src_port, unsigned int dst_ip, unsigned short dst_port);
    TCP_QUEUE_ITEM* new_tcp_queue(DIRECTION direction, unsigned int src_ip_, unsigned short src_port, unsigned int dst_ip, unsigned short dst_port, unsigned int seq, unsigned int ack);
    TCP_QUEUE_ITEM* add_to_tcp_queue(DIRECTION direction, unsigned int src_ip_, unsigned short src_port, unsigned int dst_ip, unsigned short dst_port, unsigned int seq, unsigned int ack, unsigned char *buf, int buf_size);
    
    
    void clean() {
        
    }
    FRAGMENTS_QUEUE() {
        current_ipv4_items_count = 0;
        ipv4_item_max_count = 2000;
        tcp_item_max_count = 2000;
        clean();
    }
};


#endif /* FRAGMENTS_QUEUE_H */

