/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cppFiles/file.cc to edit this template
 */

#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <map>
#include "tools.h"
#include "frame.h"

extern std::map<unsigned int, std::string> global_dns_list;

bool my_strcmp(char *s1, char *s2) {
    if(s1 == nullptr || s2 == nullptr) return false;
    int i;
    i = 0;
    while(s1[i] != 0 && s2[i] != 0 && s1[i] == s2[i]) i++;
    if( s1[i] == 0 && s2[i] == 0 ) return true;
    return false;
}


char *ipv4_to_char(unsigned int ip, char *buf) {
    buf[0] = 0;
    unsigned char *q;
    q = (unsigned char *)&ip;
    sprintf(buf, "%d.%d.%d.%d", q[3], q[2], q[1], q[0]);
    return buf;
}

unsigned short get_i16(unsigned char v1, unsigned char v2) {
    unsigned short r;
    unsigned char *q;
    q = (unsigned char *)&r;
    q[0] = v1;
    q[1] = v2;
    return r;
    
}

unsigned int get_i32(unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4) {
    unsigned int r;
    unsigned char *q;
    q = (unsigned char *)&r;
    q[0] = v1;
    q[1] = v2;
    q[2] = v3;
    q[3] = v4;
    return r;
    
}
unsigned int get_i24(unsigned char v1, unsigned char v2, unsigned char v3) {
    unsigned int r = 0;
    unsigned char *q;
    q = (unsigned char *)&r;
    q[0] = v1;
    q[1] = v2;
    q[2] = v3;
    return r;
    
}

void wtf(const char *info, int frame_no, unsigned char *buf, int buf_size) {
    printf("wtf - %s frame_no=%d buf_size=%d\n", info, frame_no, buf_size);
}
void wtf(const char *info) {
    printf("wtf - %s\n", info);
}

void save_to_file_DNS_LIST(unsigned int ip_, char *name) {
    char ip[100];
    ip[0] = 0;
    ipv4_to_char(ip_, ip);
    
    FILE *f;
    f = fopen("/var/www/html/dns_list.txt", "rb");
    if(f != NULL) {
        char cc[5][200];
        int i, j, k;
        i = fgetc(f);
        for(j=0;j<5;j++) cc[j][0] = 0;
        j = 0;
        k = 0;
        while(i!=EOF) {
            if(i == '\n') {
                if(strcmp(cc[0], ip) == 0) {
                    return;
                };
                for(j=0;j<5;j++) cc[j][0] = 0;        
                k = 0;
                j = 0;
            } else {
                if(i == '\t') {
                    if(k<5-1) k++;
                    j = 0;
                    cc[k][0] = 0;
                } else {
                    cc[k][j] = (unsigned char)i;
                    if(j<200-5) j++;
                    cc[k][j] = 0;
                }
            }
            i = fgetc(f);
        }
        fclose(f);
    };
    f = fopen("/var/www/html/dns_list.txt", "ab");
    if(f != NULL) {
        fprintf(f, "%s\t%s\n", ip, name);
        fclose(f);
    }    

}

void delete_file(char *filename) {
    FILE *f;
    f = fopen(filename, "rb");
    if(f == NULL) return;
    fclose(f);
    remove(filename);
}

void save_hex_dump_for_Wireshark(int frame_no, unsigned char *buf, int buf_size) {
    
    
    char filename[100];
    FILE *f;
    
    if(frame_no >= 10) {
        sprintf(filename, "/tmp/dump__%d.txt", frame_no-10);    
        //delete_file(filename);
    }
    
    sprintf(filename, "/tmp/dump__%d.txt", frame_no);
    
    f= fopen(filename, "wb");
    if(f != NULL) {
        int i = 0, j = 0, k = 0;
        while(i < buf_size) {
            if(j == 0) {
                fprintf(f, "%04x   ", k);
                k += 16;
                j = 16;
            }
            fprintf(f, "%02x ", buf[i]);
            j--;
            if(j == 0) fprintf(f, "\n");
            i++;
        }
        fclose(f);
    }
    
}

std::string find_dns(unsigned int ip) {
    
    std::string x;
    auto it = global_dns_list.find(ip);
    if(it == global_dns_list.end()) {
        x = "";    
    } else {
        x = it->second;
    }
    return x;    
}

bool file_exists(std::string &v) {
    FILE *f;
    f = fopen(v.c_str(), "rb");
    if(f == NULL) return false;
    fclose(f);
    return true;
}


char *decode_to_char_tcp_flag(unsigned char f, char *c) {
    unsigned char tcp_flags_cwr = (f&0x80)>>7;
    unsigned char tcp_flags_ecn = (f&0x40)>>6;
    unsigned char tcp_flags_urg = (f&0x20)>>5;
    unsigned char tcp_flags_ack = (f&0x10)>>4;
    unsigned char tcp_flags_push = (f&0x08)>>3;
    unsigned char tcp_flags_reset = (f&0x04)>>2;
    unsigned char tcp_flags_syn = (f&0x02)>>1;
    unsigned char tcp_flags_fin = (f&0x01);
    sprintf(c, "%c%c%c%c%c%c%c%c", tcp_flags_cwr == 0 ? '-' : 'c'
                         , tcp_flags_ecn == 0 ? '-' : 'e'
                         , tcp_flags_urg == 0 ? '-' : 'u'
                         , tcp_flags_ack == 0 ? '-' : 'A'
            
                         , tcp_flags_push == 0 ? '-' : 'p'
                         , tcp_flags_reset == 0 ? '-' : 'r'
                         , tcp_flags_syn == 0 ? '-' : 'S'
                         , tcp_flags_fin == 0 ? '-' : 'f'
            );
    return c;
}

void rewrite_in_file_A(char *filename, unsigned char ip_proto, int frame_size) {
    FILE *f;
    f = fopen(filename, "r+");
    if(f == NULL) return;
    int i, j, k;
    
    char pref[100], cc[1000], vv[100];
    if(ip_proto == 6) {
        sprintf(pref,"TCP");
    } else if(ip_proto == 17) {
        sprintf(pref,"UDP");
    } else {
        sprintf(pref,"%02X", ip_proto);
    }
    
    i = fgetc(f);
    j = 0;
    while(i != EOF) {
        if(i == '\n') {
            j = 0;
            cc[0] = 0;
        } else {
            if( i == ':' ) {
                if(my_strcmp(cc, pref)==true) {
                    for(int i=0;i<20;i++) vv[i] = 0;
                    k = fread(vv, 1, 10, f);
                    int v1 = atoi(vv);
                    if(k != 10) {
                        fclose(f);
                        return;
                    }
                    fseek(f, -10, SEEK_CUR);
                    k = fprintf(f, "%010d", frame_size + v1);
                    fclose(f);
                    return;
                }
            } else {
                cc[j] = (char)i;
                if(j<1000-5) j++;
                cc[j] = 0;
            }
        }
        i = fgetc(f);    
    }
    fclose(f);
}


void detect_ip(FRAME *frame) {
    unsigned char ip_proto_;
    int ip0_, port0_, ip1_, port1_, frame_size_;
    if(frame->direction == egress) {
        ip1_ = frame->ipv4_dst_ip;
        port1_ = frame->ipv4_dst_port;
        
        ip0_ = frame->ipv4_src_ip;
        port0_ = frame->ipv4_src_port;
        
    } else {
        ip1_ = frame->ipv4_src_ip;
        port1_ = frame->ipv4_src_port;
        
        ip0_ = frame->ipv4_dst_ip;
        port0_ = frame->ipv4_dst_port;
    }
    frame_size_ = frame->payload_size;
    
    if(ip1_ == 0) return;
    if(ip1_ == 0xffffffff) return;
    if((ip1_ & 0xff000000) == 0xc0000000 &&
       (ip1_ & 0xff0000) == 0xa80000 )
    {
        
        return;
    }

    if(ip1_ == 0x08080808 || ip0_ == 0x08080808) {
        return;
    }
    
    char ss[500], ip0__[100], ip1__[100];
    ipv4_to_char(ip1_, ip1__);
    ipv4_to_char(ip0_, ip0__);
    
    sprintf(ss, "/var/www/html/sniffer_web/ip3/%s:%d_%s:%d", ip1__, port1_, ip0__, port0_);
    
    char tcp_e[1000], udp_e[1000], sni[1000], cert[1000];
    char tcp_i[1000], udp_i[1000];
    tcp_e[0] = 0;
    udp_e[0] = 0;
    tcp_i[0] = 0;
    udp_i[0] = 0;
    sni[0] = 0;
    cert[0] = 0;
    int i,j,jj,k,v;
    
    FILE *f;
    f = fopen(ss, "rb");
    if( f != NULL ){
        i = fgetc(f);
        j = 0;
        jj = 0;
        k = 0;
        v = 0;
        while(i != EOF) {
            if(i == '\n') {
                j = 0;
                jj = 0;
                v = 0;
                if(k < 3) k++;
                
            } else {
                if(i == ':') {
                    v++;
                } else {
                    if(v==1) {
                        if(k == 0) { tcp_e[j] = i; tcp_e[j+1] = 0; };
                        if(k == 1) { udp_e[j] = i; udp_e[j+1] = 0; };
                        if(k == 2) { sni[j] = i; sni[j+1] = 0; };
                        if(k == 3) { cert[j] = i; cert[j+1] = 0; };
                        if(j<1000-5) j++;
                    };
                    if(v==2) {
                        if(k == 0) { tcp_i[jj] = i; tcp_i[jj+1] = 0; };
                        if(k == 1) { udp_i[jj] = i; udp_i[jj+1] = 0; };
                        if(jj<1000-5) jj++;
                    };
                }
            }
            i = fgetc(f);
        }
        fclose(f);
        //rewrite_in_file_A(ss, ip_proto, frame_size);
        
        //return;
    }
    
    f = fopen(ss, "wb");
    if(f == nullptr) {
        printf("f == nullptr\n");
        return;
    }
    
    int tcp_val_e = atoi(tcp_e);
    int udp_val_e = atoi(udp_e);
    int tcp_val_i = atoi(tcp_i);
    int udp_val_i = atoi(udp_i);
    
    
    if(frame->ip_proto == 6) { 
        if(frame->direction == egress) {
            tcp_val_e += frame_size_;
        } else {
            tcp_val_i += frame_size_;
        }
    } else if(frame->ip_proto == 17) { 
        if(frame->direction == egress) {
            udp_val_e += frame_size_;
        } else {
            udp_val_i += frame_size_;
        }
    } else {
        
    }

    std::string aa;
    if(sni[0] == 0) {
        for(auto &a: frame->SNI) {
            if(sni[0] != 0 && strlen(sni) < 1000-100) strcat(sni, ",");
            if(strlen(sni) + strlen(a.c_str()) < 1000-10) strcat(sni, a.c_str());
        }
    };
   
    
    if(cert[0] == 0) {
        
        
            int xx = frame->get_cert_count();
            
            if(xx > 0) {
                sprintf(cert, "%d", xx);
            };
        
    };
    
    if(sni[0] == 'd') {
        printf("d\n");
    }
    
    
    fprintf(f, "tcp:%05d:%05d\n", tcp_val_e, tcp_val_i);
    fprintf(f, "udp:%05d:%05d\n", udp_val_e, udp_val_i);   
    fprintf(f, "sni:%s\n", sni);
    fprintf(f, "cert:%s\n", cert);
    
    fclose(f);
    
    //analiz_by_patterns(frame);
}



bool DirectoryExists( const char* pzPath )
{
    if ( pzPath == NULL) return false;

    DIR *pDir;
    bool bExists = false;

    pDir = opendir (pzPath);

    if (pDir != NULL)
    {
        bExists = true;    
        (void) closedir (pDir);
    }

    return bExists;
}
int to_integer( const char *v ) {
    int i, r = 0;
    i = 0;
    while(v[i] != 0) {
        if(v[i] < '0' || v[i] > '9') return 0;
        r *= 10;
        r += ((int)v[i])-((int)'0');
        i++;
    }
    return r;
}

void create_file(const char *dir, unsigned int n) {
    FILE *f;
    char ss[500], c1[100];
    ipv4_to_char(n, c1);
    sprintf(ss, "%s/%s", dir, c1);
    f = fopen(ss, "wb");
    if(f != NULL) {
        fclose(f);
    }
    chmod(ss, ALLPERMS);
}

void analiz_by_patterns(FRAME *frame) {
    FILE *f;
    
    if(frame->ip_proto == 17) { // udp
        if(frame->direction == egress) {
            if(frame->ipv4_dst_port == 4500) {
                create_file("/var/www/html/need_block", frame->ipv4_dst_ip);
            }            
        }
    }
}