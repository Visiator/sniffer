/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cFiles/file.h to edit this template
 */

/* 
 * File:   tools.h
 * Author: smorodin
 *
 * Created on July 15, 2022, 10:33 AM
 */

#ifndef TOOLS_H
#define TOOLS_H

#include "frame.h"

#include <string>
#include <stdio.h>
#include <string.h>

class FRAME;

void save_to_file_DNS_LIST(unsigned int ip_, char *name);
void save_hex_dump_for_Wireshark(int frame_no, unsigned char *buf, int buf_size);

void wtf(const char *info, int frame_no, unsigned char *buf, int buf_size);
void wtf(const char *info);

unsigned short get_i16(unsigned char v1, unsigned char v2);
unsigned int get_i32(unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4);
unsigned int get_i24(unsigned char v1, unsigned char v2, unsigned char v3);


char *ipv4_to_char(unsigned int ip, char *buf);

std::string find_dns(unsigned int ip);

bool file_exists(std::string &v);

char *decode_to_char_tcp_flag(unsigned char f, char *c);

void detect_ip(FRAME *frame);

bool DirectoryExists( const char* pzPath );

int to_integer( const char *v );
void analiz_by_patterns(FRAME *frame);
void create_file(const char *dir, unsigned int n);

#endif /* TOOLS_H */

