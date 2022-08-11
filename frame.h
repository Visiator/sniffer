/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cFiles/file.h to edit this template
 */

/* 
 * File:   frame.h
 * Author: smorodin
 *
 * Created on July 15, 2022, 11:30 AM
 */

#ifndef FRAME_H
#define FRAME_H

#include <string>
#include <vector>
#include <list>
#include <iterator>


#include "tools.h"

enum DIRECTION {undefined, ingress, egress};

class CERT {
public:
    
    unsigned char ver;
    unsigned char serial[100];
    int serial_sz;
    bool sha256WithRSAEncryption;
    bool rsaEncryption;
    std::string countryName, localityName, orgName, orgUnitName, commonName, stateName;
    unsigned char key512[512], key256[256], mod3[3];
    bool is_key256_m3;
    bool is_key256;
    bool is_key512;
    bool is_key512_m3;
    void detect_bitstring2048_m3(unsigned char *key256_, unsigned char *mod3_) {
        for(int i=0;i<256;i++) key256[i] = key256_[i];
        for(int i=0;i<3;i++)   mod3[i] = mod3_[i];
        is_key256_m3 = true;
    }
    void detect_bitstring2048(unsigned char *key256_) {
        for(int i=0;i<256;i++) key256[i] = key256_[i];
        is_key256 = true;
    }
    void detect_bitstring4096(unsigned char *key512_) {
        for(int i=0;i<512;i++) key512[i] = key512_[i];
        is_key512 = true;
    }
    void detect_bitstring4096_m3(unsigned char *key512_, unsigned char *mod3_) {
        for(int i=0;i<512;i++) key512[i] = key512_[i];
        for(int i=0;i<3;i++)   mod3[i] = mod3_[i];
        is_key512_m3 = true;
    }
    void set_object(std::string& name, std::string& value) {
        
        if(name == "rsaEncryption") {
            rsaEncryption = true;
            return;
        }
        if(name == "sha256WithRSAEncryption") {
            sha256WithRSAEncryption = true;
            return;
        }
        if(name == "countryName") {
            if(countryName != "") countryName += ",";
            countryName += value;
            return;
        };
        if(name == "localityName") {
            if(localityName != "") localityName += ",";
            localityName += value;
            return;
        };
        if(name == "orgName") {
            if(orgName != "") orgName += ",";
            orgName += value;
            return;
        };
        if(name == "orgUnitName") {
            if(orgUnitName != "") orgUnitName += ",";
            orgUnitName += value;
            return;
        };
        if(name == "commonName") {
            if(commonName != "") commonName += ",";
            commonName += value;
            return;
        };
        if(name == "stateName") {
            if(stateName != "") stateName += ",";
            stateName += value;
            return;
        };
        //wtf("?");
    }
    void set_serial16(unsigned char *v) {
        for(int i=0;i<16;i++) serial[i] = v[i];
        serial_sz = 16;
    }
    void set_ver(unsigned char v_) { ver = v_; };
    
    void clean() {
        for(int i=0;i<100;i++) serial[i] = 0;
        serial_sz = 0;
        ver = 0;
        rsaEncryption = false;
        sha256WithRSAEncryption = false;
        countryName = "";
        localityName = "";
        orgName = "";
        orgUnitName = "";
        commonName = "";
        stateName = "";
        for(int i=0;i<512;i++) key512[i] = 0;
        for(int i=0;i<256;i++) key256[i] = 0;
        for(int i=0;i<3;i++)   mod3[i] = 0;
        is_key256_m3 = false;
        is_key256 = false;
        is_key512 = false;
        is_key512_m3 = false;
    }
    
    CERT() {
        clean();
    }
};

class FRAME {
public:
 
    std::string session_id;
    unsigned short ethernet_ii_type;
    unsigned char mac_src[6], mac_dst[6];
    unsigned char ip_proto; 
    unsigned int ipv4_src_ip, ipv4_dst_ip;
    unsigned short ipv4_src_port, ipv4_dst_port;
    DIRECTION direction; // ingress, egress
    bool dhcp_request, dhcp_responce;
    bool dns_request, dns_responce;
    std::string dns_request_name;
    std::string dns_responce_name;
    unsigned int session_size, session_payload_size, session_packet_count, session_packet_with_payload_count;
    bool is_ipv4_fragment;
    std::vector<CERT> cert_list;
    int cert_count;
    bool sess_is_saved;
    unsigned char *eth2_buf;
    int eth2_buf_size;
    
    int get_cert_count() { 
        int r;
        if(cert_count>0) {
            r = cert_count;
        }
        r = 0;
        for(auto &a: cert_list) {
            r++;
        }
        return r; 
    };
    
    void save_sess(int frame_no_, unsigned char *buf_, int buf_size_);
    void save_pcap(int frame_no_, unsigned char *buf_, int buf_size_);
    void add_cert(CERT &cert) {
        cert_count++;
        cert_list.push_back(cert);
    }
    
    void add_dns_request(char *str) {
        if(dns_request_name != "") dns_request_name += ",";
        dns_request_name += str;
    }
    
    unsigned char *payload;
    int frame_size, payload_size;
    
    bool tls_160301, tls_160303, tls_140303, tls_170303;
    std::string EC_Diffie_Hellman_Client_Params;
    std::vector<std::string> SNI;
    void set_SNI(char *v) {
        std::string s;
        s = std::string(v);
        for (unsigned int i = 0; i < SNI.size(); i++) {
            if(SNI[i] == s) {
                return;
            }
        }
        
        SNI.emplace_back(s);
    }
    unsigned char ClientHello_Key51[130];
    void set_ClientHello_Key51(unsigned char *n, int n_len) {
        int i;
        i = 0;
        while(i < 130-2 && i < n_len) {
            ClientHello_Key51[i] = n[i];
            i++;
        }
        ClientHello_Key51[i] = 0;
    }
    bool stored_to_session_;
    void save_first_packert();
    void set_mac_src(unsigned char *v);
    void set_mac_dst(unsigned char *v);
    void set_ipv4_src_ip(unsigned int v);
    void set_ipv4_dst_ip(unsigned int v);
    void set_ipv4_src_port(unsigned short v) { ipv4_src_port = v; };    
    void set_ipv4_dst_port(unsigned short v) { ipv4_dst_port = v; };
    void set_dns_request(char *rr, unsigned short dns_qry_type, unsigned short dns_qry_class);
    void add_dns_responce(char *name, unsigned int ip);
    void detect_direction();
    std::string generate_id_from_FRAME_ipv4(FRAME *frame);
    void get_packet_no_from_session();
    void stored_to_session() {
        stored_to_session_ = true;
    }
    bool is_wireguard_cs;
    bool is_wireguard_sc;
    unsigned char wg_sender[4];
    unsigned char wg_ephemeral[32];
    void set_wg_sender(unsigned char *buf) {
        for(int i=0;i<4;i++) wg_sender[i] = buf[i];
        is_wireguard_cs = true;
    }
    void set_wg_ephemeral(unsigned char *buf) {
        for(int i=0;i<32;i++) wg_ephemeral[i] = buf[i];
    }
    void clean() {
        is_ipv4_fragment = false;
        for(int i=0;i<130;i++) ClientHello_Key51[i] = 0;
        for(int i=0;i<4;i++) wg_sender[i] = 0;
        for(int i=0;i<32;i++) wg_ephemeral[i] = 0;
        is_wireguard_cs = false;
        is_wireguard_sc = false;
        
        stored_to_session_ = false;
        cert_list.clear();
        cert_count = 0;
        SNI.clear();
        tls_160301 = false;
        tls_160303 = false;
        tls_140303 = false;
        tls_170303 = false;
        EC_Diffie_Hellman_Client_Params = "";
        dns_request_name = "";
        dns_responce_name = "";;
        dhcp_request = false;
        dhcp_responce = false;
        dns_request = false;
        dns_responce = false;
        ip_proto = 0;
        session_id = "";
        frame_size = 0;
        payload = nullptr;
        payload_size = 0;
        direction = undefined;
        ipv4_src_ip = 0;
        ipv4_dst_ip = 0;
        ipv4_src_port = 0;
        ipv4_dst_port = 0;
        ethernet_ii_type = 0;
        for(int i=0;i<6;i++) { mac_dst[i] = 0; mac_src[i] = 0; };
        
        sess_is_saved = false;
        session_size = 0;
        session_payload_size = 0;
        session_packet_count = 0;
        session_packet_with_payload_count = 0;
        
        eth2_buf = nullptr;
        eth2_buf_size = 0;
        
    }
    char *direction_to_char(char *c) {
        if(direction == undefined) return (char *)" ?? ";
        if(direction == ingress) return (char *)" <- ";
        if(direction == egress) return (char *)" -> ";
        return (char *)"?";
    }
    FRAME();
};

#endif /* FRAME_H */

