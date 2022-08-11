#include "fragments_queue.h"
#include "tools.h"

TCP_QUEUE_ITEM* FRAGMENTS_QUEUE::new_tcp_queue(DIRECTION direction, unsigned int src_ip_, unsigned short src_port, unsigned int dst_ip, unsigned short dst_port, unsigned int seq, unsigned int ack) {
    int i = 0;
    while(i < tcp_item_max_count) {
        if(tcp_item[i].compare(direction, src_ip_, src_port, dst_ip, dst_port)) {
            return &tcp_item[i];
        }
        i++;
    }
    i = 0;
    while(i < tcp_item_max_count) {
        if(tcp_item[i].is_empty()) {
            tcp_item[i].first_set(direction, src_ip_, src_port, dst_ip, dst_port, seq, ack);
            return &tcp_item[i];
        }
        i++;
    }
    return nullptr;   
}

IPV4_QUEUE_ITEM* FRAGMENTS_QUEUE::new_ipv4_queue(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id) {
    int i = 0;
    while(i < ipv4_item_max_count) {
        if(ipv4_item[i].compare(ip_proto, ip_src, ip_dst, ip_id)) {
            return &ipv4_item[i];
        }
        i++;
    }
    i = 0;
    while(i < ipv4_item_max_count) {
        if(ipv4_item[i].is_empty()) {
            current_ipv4_items_count++;
            ipv4_item[i].first_set(ip_proto, ip_src, ip_dst, ip_id);
            return &ipv4_item[i];
        }
        i++;
    }
    return nullptr;
}

TCP_QUEUE_ITEM* FRAGMENTS_QUEUE::find_tcp_queue(DIRECTION direction, unsigned int src_ip_, unsigned short src_port_, unsigned int dst_ip_, unsigned short dst_port_) {
    int i = 0;
    while(i < tcp_item_max_count) {
        if(tcp_item[i].compare(direction, src_ip_, src_port_, dst_ip_, dst_port_)) {
            return &tcp_item[i];
        }
        i++;
    }
    return nullptr;
    
}

IPV4_QUEUE_ITEM* FRAGMENTS_QUEUE::find_ipv4_queue(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id) {
    int i = 0;
    while(i < ipv4_item_max_count) {
        if(ipv4_item[i].compare(ip_proto, ip_src, ip_dst, ip_id)) {
            return &ipv4_item[i];
        }
        i++;
    }
    return nullptr;
}



TCP_QUEUE_ITEM* FRAGMENTS_QUEUE::add_to_tcp_queue(DIRECTION direction_, unsigned int src_ip_, unsigned short src_port_, unsigned int dst_ip_, unsigned short dst_port_, unsigned int seq_, unsigned int ack_, unsigned char *buf_, int buf_size_) {
    TCP_QUEUE_ITEM *q;
    q = find_tcp_queue(direction_, src_ip_, src_port_, dst_ip_, dst_port_);
    if(q == nullptr) {
        q = new_tcp_queue(direction_, src_ip_, src_port_, dst_ip_, dst_port_, seq_, ack_);
    }
    if(q == nullptr) {
        wtf("add_to_tcp_queue");
        return nullptr;
    }
    unsigned int d1, d2;
    //if(direction_ == ingress) {
        if(seq_ < q->seq_first) { wtf("seq_ < q->seq_first"); return nullptr; };
        if(seq_ < q->seq_old) { wtf("seq_ < q->seq_old"); return nullptr; };
        d1 = seq_ - q->seq_first;
        d2 = seq_ - q->seq_old;
    //}
    q->add_fragment(buf_, buf_size_, d1);
    q->seq_old = seq_;
    q->ack_old = ack_;
    
    return q;
}

IPV4_QUEUE_ITEM* FRAGMENTS_QUEUE::add_to_ipv4_queue(unsigned char ip_proto, unsigned int ip_src, unsigned int ip_dst, unsigned short ip_id, unsigned short fragment_offset, unsigned char *buf, int buf_size) {
    IPV4_QUEUE_ITEM *q;
    q = find_ipv4_queue(ip_proto, ip_src, ip_dst, ip_id);
    if(q == nullptr) {
        q = new_ipv4_queue(ip_proto, ip_src, ip_dst, ip_id);
    }
    if(q == nullptr) {
        wtf("add_to_ipv4_queue");
        return nullptr;
    }
    q->add_fragment(buf, buf_size, fragment_offset);
    return q;
}