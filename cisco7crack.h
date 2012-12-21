/* Header file for CISCO7CRACK.C - Sat Oct 19, 2002
 * (C) 2002 by Davide Madrisan <davide.madrisan@google.com>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your  option)  any  later
 * version.
 *
 * This program is distributed in the hope that it will be useful,  but  WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 */


/* IOS cuts passwords with length > `MAX_PLAIN_LEN' (25 in IOS 12.0(7)T)
 * Note that some passwords, like OSPF authentication keys, are even shorter */
#define MAX_PLAIN_LEN 25
/* NOTE: if you increment this value you can generate passwords that are _not_
 * IOS-compliant */
#define MAX_XOR_OFFSET 15

/* next directive is intended to support (at least) routers C761
   with IOS(?) c760-in.r.NET3 4.2(3).  They use lowercase letters in 'hex'
   (i.e. 0123456789abcdef)
   thanks to Fabrizio Pedracini for the info */
/* #define HEX_LOWER_SUPPORT */

#define MAX_ENCRYPTED_LEN (2+(2*MAX_PLAIN_LEN)+1)
#define min(x,y) ((x) < (y) ? (x) : (y))

/* return codes of this program ([no] errors, warnings) */
#define ERR_NONE                0x00
#define ERR_USAGE               0x01
#define ERR_INPUT_ILLEGAL_CHAR  0x02
#define ERR_INPUT_ODD_DIGITS    0x04
#define ERR_INPUT_TOO_LONG      0x08

#define OFFSET_RANDOM -1
#define OFFSET_ALL    -2

#define PROGRAM  "cisco7crack"
#define AUTHOR   "Davide Madrisan <davide.madrisan@atlavia.it>"
#define VERSION  "v2.3.4 - San Oct 19, 2002"


static const char *dec = "0123456789", *hex = "0123456789ABCDEF";
static const char magic[] = {
     0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
     0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
     0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42
};                              /* "dsfd;kfoA,.iyewrkldJKDHSUB" */
const unsigned int magic_size = sizeof(magic) / sizeof(magic[0]);

typedef enum e_bool { false = 0, true } bool;
typedef struct s_options {      /* arguments passed on command line */
     bool crypt;
     bool decrypt;
     bool quiet;
     int xor_offset;
} options_list;
options_list opt;

void usage(void);
int decrypt_str(const char *passwd);
int crypt_str(const char *str2crypt, int xor_offset);
unsigned int get_entropy(void);
void cfprintf(FILE * stream, const char *fmt, ...);
#ifdef HEX_LOWER_SUPPORT
char *strtoupper(char *str);
#endif
