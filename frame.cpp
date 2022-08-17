
#include <vector>
#include <map>


#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include "frame.h"
#include "sessions.h"
#include "tools.h"

extern std::map<unsigned int, std::string> global_dns_list;
extern SESSIONS sessions;


FRAME::FRAME() {
    clean();
}

void FRAME::set_mac_src(unsigned char *v) {
    for(int i=0;i<6;i++) mac_src[i] = v[i];
}

void FRAME::set_mac_dst(unsigned char *v) {
    for(int i=0;i<6;i++) mac_dst[i] = v[i];    
}

void FRAME::set_ipv4_src_ip(unsigned int v) { 
    ipv4_src_ip = v; 
};    
   
void FRAME::set_ipv4_dst_ip(unsigned int v) { 
    ipv4_dst_ip = v; 
};

void FRAME::set_dns_request(char *rr, unsigned short dns_qry_type, unsigned short dns_qry_class) {
    
    if(dns_request_name != "") dns_request_name += ",";
    dns_request_name += rr;
}

void FRAME::add_dns_responce(char *name, unsigned int ip) {

    char cc[100];
    ipv4_to_char(ip, cc);
    if(dns_responce_name != "") dns_responce_name += ",";
    dns_responce_name += std::string(cc) + ":" + name;

    std::string s;
    s = name;
    std::pair<unsigned int, std::string> pp;
    pp = std::make_pair(ip, s);

    
 
    global_dns_list.insert(pp);  
    
    save_to_file_DNS_LIST(ip, name);
}

void FRAME::detect_direction() {
    if( ((ipv4_src_ip & 0xff000000) == 0xc0000000) &&
            ((ipv4_src_ip & 0xff0000) == 0xa80000) 
      ) 
    {
        direction = egress;
        return;
    }

    if( ((ipv4_src_ip & 0xff000000) == 0x0a000000) &&
            ((ipv4_src_ip & 0xff0000) == 0xd40000) 
      ) 
    {
        direction = egress;
        return;
    }

    
    if( ((ipv4_dst_ip & 0xff000000) == 0xc0000000) &&
        ((ipv4_dst_ip & 0xff0000) == 0xa80000) 
      ) 
    {
        direction = ingress;
        return;
    }
    if( ((ipv4_dst_ip & 0xff000000) == 0x0a000000) &&
        ((ipv4_dst_ip & 0xff0000) == 0xd40000) 
      ) 
    {
        direction = ingress;
        return;
    }

}

char *decode_ip_proto(unsigned char v, char *c) {
    
    if(v == 6) {
        sprintf(c, "TCP");
    } else if(v == 17) {
        sprintf(c, "UDP");
    } else {        
        sprintf(c, "%d", v);
    }
    
    return c;
}

std::string FRAME::generate_id_from_FRAME_ipv4(FRAME *frame) {
    char c0[100], c1[100], c2[100], ss[1000];
    std::string x;
    
    if(frame->direction == egress) {
        
        sprintf(ss, "%s %s:%d - %s:%d", decode_ip_proto(frame->ip_proto, c0), ipv4_to_char(frame->ipv4_dst_ip, c1), frame->ipv4_dst_port, ipv4_to_char(frame->ipv4_src_ip, c2), frame->ipv4_src_port);
        x += std::string(ss);
    } else {
        sprintf(ss, "%s %s:%d - %s:%d", decode_ip_proto(frame->ip_proto, c0), ipv4_to_char(frame->ipv4_src_ip, c2), frame->ipv4_src_port, ipv4_to_char(frame->ipv4_dst_ip, c1), frame->ipv4_dst_port);
        x += std::string(ss);
    }
    
    return x;
}

void FRAME::get_packet_no_from_session() {
    
    auto it = sessions.items.find(session_id);
    if(it == sessions.items.end()) return;
    
    session_size = it->second.size;
    session_payload_size = it->second.payload_size;
    session_packet_count = it->second.packet_count;
    session_packet_with_payload_count = it->second.packet_with_payload_count;
    
}

void FRAME::save_first_packert() {
    if(this->payload_size > 0 && this->session_packet_with_payload_count == 0) {
        FILE *f;
        char nf[500];
        sprintf(nf, "/var/www/html/sessions/%s", this->session_id.c_str());
        f = fopen(nf, "wb");
        if(f != NULL) {
            for(auto& a: SNI) {
                fprintf(f, "sni: %s\n", a.c_str());
            }
            int i = 1;
            for(auto& c: cert_list) {
                fprintf(f, "cert: %d\n", i);
                if(c.commonName != "") fprintf(f,"cert: %s\n", c.commonName.c_str());
                i++;
            }
            fprintf(f, "-----\n");
            fwrite(this->payload, 1, this->payload_size, f);
            fclose(f);
        }
    };
}

unsigned char tmpl[] = { 
    0x0a, 0x0d, 0x0d, 0x0a, 0xdc, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x3c, 0x00, 0x31, 0x31, 0x74, 0x68, 0x20, 0x47, 0x65, 0x6e, 0x20, 0x49, 0x6e, 0x74, 
0x65, 0x6c, 0x28, 0x52, 0x29, 0x20, 0x43, 0x6f, 0x72, 0x65, 0x28, 0x54, 0x4d, 0x29, 0x20, 0x69, 0x37, 0x2d, 0x31, 0x31, 
0x36, 0x35, 0x47, 0x37, 0x20, 0x40, 0x20, 0x32, 0x2e, 0x38, 0x30, 0x47, 0x48, 0x7a, 0x20, 0x28, 0x77, 0x69, 0x74, 0x68, 
0x20, 0x53, 0x53, 0x45, 0x34, 0x2e, 0x32, 0x29, 0x03, 0x00, 0x17, 0x00, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x35, 0x2e, 
0x31, 0x35, 0x2e, 0x30, 0x2d, 0x34, 0x33, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x00, 0x04, 0x00, 0x5b, 0x00, 
0x44, 0x75, 0x6d, 0x70, 0x63, 0x61, 0x70, 0x20, 0x28, 0x57, 0x69, 0x72, 0x65, 0x73, 0x68, 0x61, 0x72, 0x6b, 0x29, 0x20, 
0x33, 0x2e, 0x36, 0x2e, 0x35, 0x20, 0x28, 0x47, 0x69, 0x74, 0x20, 0x76, 0x33, 0x2e, 0x36, 0x2e, 0x35, 0x20, 0x70, 0x61, 
0x63, 0x6b, 0x61, 0x67, 0x65, 0x64, 0x20, 0x61, 0x73, 0x20, 0x33, 0x2e, 0x36, 0x2e, 0x35, 0x2d, 0x31, 0x7e, 0x75, 0x62, 
0x75, 0x6e, 0x74, 0x75, 0x32, 0x30, 0x2e, 0x30, 0x34, 0x2e, 0x30, 0x2b, 0x77, 0x69, 0x72, 0x65, 0x73, 0x68, 0x61, 0x72, 
0x6b, 0x64, 0x65, 0x76, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0x00, 0x00, 0x00, 
0x01, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x05, 0x00, 
0x74, 0x7a, 0x73, 0x70, 0x30, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x17, 0x00, 
0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x35, 0x2e, 0x31, 0x35, 0x2e, 0x30, 0x2d, 0x34, 0x33, 0x2d, 0x67, 0x65, 0x6e, 0x65, 
0x72, 0x69, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 1 };


FILE *create_pcap_file(char *file_name) {
    char ss[500], bb[1000];
    int j, i;
    j = 0;
    FILE *f;
    
    f = fopen(file_name, "wb");
    if(f == NULL) {
        wtf("f == NULL");
        return NULL;
    }
    i = 0;
    for(i=0;i<292;i++){
        fprintf(f, "%c", tmpl[i]);
    }
    
    //fwrite(bb, 1, j, f);
    return f;
}

FILE *open_pcap_file(char *file_name) {
    return fopen(file_name, "ab");
}

unsigned int vv4(unsigned int v) {
    unsigned int r;
    r = v % 4;
    if(r == 0) return 0;
    return 4 - r;
}

void FRAME::save_pcap(int frame_no_, unsigned char *buf_, int buf_size_) {
    char fn[1000];
    sprintf(fn, "/var/www/html/sniffer_web/sess/%s", this->session_id.c_str());
    
    //bool r = DirectoryExists(fn);
    if(!DirectoryExists(fn)) {
        mkdir(fn, 0777);
        chmod(fn, 0777);
    }
    
    sprintf(fn, "/var/www/html/sniffer_web/sess/%s/_sess.pcap", this->session_id.c_str());
    FILE *f;
    f = fopen(fn, "rb");
    if(f == NULL) {
        
        f = create_pcap_file(fn);
    } else {
        fclose(f);  
        f = open_pcap_file(fn);
    }
    
    
    unsigned int v = 6, i, sz, sz2, sz3;
    sz = buf_size_;
    sz2 = sz + 20; 
    sz2 += vv4(sz2);
    sz3 = sz2 + 12;
    
    
    fwrite(&v, 1, 4, f); // 6
    
    fwrite(&sz3, 1, 4, f);
    i = 0;
    fwrite(&i, 1, 4, f);
    i = 0;
    fwrite(&i, 1, 4, f);
    fwrite(&i, 1, 4, f);
    fwrite(&sz, 1, 4, f);
    fwrite(&sz, 1, 4, f);

    fwrite(buf_, 1, buf_size_, f);
    v = buf_size_ % 4;
    if(v>0) for(i=0;i<4-v;i++) fprintf(f, "%c", 0);
    fwrite(&sz3, 1, 4, f);
    fclose(f);
}

void FRAME::save_sess(int frame_no_, unsigned char *buf_, int buf_size_) {
    sess_is_saved = true;
    
    char dir[] = {"/var/www/html/sniffer_web/sess"};
    
    bool r = DirectoryExists(dir);
    if(!DirectoryExists(dir)) {
        mkdir(dir, 0777);
        chmod(dir, 0777);
    }
    
    FILE *f = NULL;
    char dd[1000];
    sprintf(dd, "%s/%s", dir, this->session_id.c_str());
    if(!DirectoryExists(dd)) {
        mkdir(dd, 0777);
        chmod(dd, 0777);
        //f = create_pcap_file(dd);
    } else {
        //f = open_pcap_file(dd);
    }
    
    /*if(f != NULL) {
        unsigned int v = 6, i, ssz;
        ssz = buf_size_ + 12;
        fwrite(&v, 1, 4, f);
        fwrite(&ssz, 1, 4, f);
        i = 1;
        fwrite(&i, 1, 4, f);
        i = 0;
        fwrite(&i, 1, 4, f);
        fwrite(&i, 1, 4, f);
        fwrite(&buf_size_, 1, 4, f);
        fwrite(&buf_size_, 1, 4, f);
        
        fwrite(buf_, 1, buf_size_, f);
        v = buf_size_ % 4;
        if(v>0) for(i=0;i<4-v;i++) fprintf(f, "%c", 0);
        fwrite(&ssz, 1, 4, f);
        fclose(f);
    }*/
    
    std::string ss, sni, cert;
    
    char mm[2000];
    sprintf(mm, "%s/%05d - %s", dd, frame_no_, direction == ingress ? "in" : direction == egress ? "out" : "n");
    ss = mm;
    if(SNI.size() > 0) {
        ss += " sni";
    }
    if(cert_list.size() > 0) {
        ss += " cert";
    }
    

    f = fopen(ss.c_str(), "wb");
    if(f != NULL) {
        fprintf(f, "frame_no: %d\n", frame_no_);
        fprintf(f, "id: %s\n", session_id.c_str());
        fprintf(f, "ip_proto: %d\n", ip_proto);
        fprintf(f, "direction: %d\n", direction);
        
        
        fprintf(f, "payload size: %d\n", buf_size_);
        for(auto &a: SNI) {
            fprintf(f, "sni: %s\n", a.c_str());    
        }
        int xx;
        xx = 0;
        /*
        for(auto &c: cert_list) {
            fprintf(f, "=== cert: %d\n", xx);    
            
            if(c.countryName != "") fprintf(f, "countryName: %s\n", c.countryName.c_str());
            if(c.localityName != "") fprintf(f, "localityName: %s\n", c.localityName.c_str());
            if(c.orgName != "") fprintf(f, "orgName: %s\n", c.orgName.c_str());
            if(c.commonName != "") fprintf(f, "commonName: %s\n", c.commonName.c_str());
            if(c.stateName != "") fprintf(f, "stateName: %s\n", c.stateName.c_str());
            if(c.serial_sz != 0) {
                if(c.serial_sz == 16) {
                    fprintf(f, "serial_sz: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n"
                            , c.serial[0], c.serial[1], c.serial[2], c.serial[3]
                            , c.serial[4], c.serial[5], c.serial[6], c.serial[7]
                            , c.serial[8], c.serial[9], c.serial[10], c.serial[11]
                            , c.serial[12], c.serial[13], c.serial[14], c.serial[15]
                            );
                } else {
                    fprintf(f, "serial_sz: %d\n", c.serial_sz);
                };
            };
            
            if(c.sha256WithRSAEncryption != 0) fprintf(f, "sha256WithRSAEncryption: set\n");
            if(c.rsaEncryption != 0) fprintf(f, "rsaEncryption: set\n");

            if(c.is_key256_m3 != 0) fprintf(f, "is_key256_m3: set\n");
            if(c.is_key256 != 0) fprintf(f, "is_key256: set\n");
            if(c.is_key512 != 0) fprintf(f, "is_key512: set\n");
            if(c.is_key512_m3 != 0) fprintf(f, "is_key512_m3: set\n");
            xx++;
        }
        */
        fprintf(f, "-----\n");
        fwrite(buf_, 1, buf_size_, f);
        
        fclose(f);
    }
    
    //************************************************************************************************************//
    sprintf(mm, "%s/w_%05d - %s", dd, frame_no_, direction == ingress ? "in" : direction == egress ? "out" : "n");
    ss = mm;
    if(SNI.size() > 0) {
        ss += " sni";
    }
    if(cert_list.size() > 0) {
        ss += " cert";
    }
    
    f = fopen(ss.c_str(), "wb");
    if(f != NULL) {
        //fwrite(this->eth2_buf, 1, this->eth2_buf_size, f);
        int i = 0, j = 0, k = 0;
        while(i < eth2_buf_size) {
            if(j == 0) {
                fprintf(f, "%04x   ", k);
                k += 16;
                j = 16;
            }
            fprintf(f, "%02x ", eth2_buf[i]);
            j--;
            if(j == 0) fprintf(f, "\n");
            i++;
        }
        fclose(f);
    }
    
    
    
}