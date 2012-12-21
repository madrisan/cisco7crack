#if 0
gcc -Wall -W -ansi -pedantic -O2 cisco7crack.c -o cisco7crack || exit 1
echo successfully compiled
exit
#endif   /* Compile with:  sh ./cisco7crack.c */

/* CISCO7CRACK.C ver. 2.3.4 - San Oct 19, 2002
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
 *
 * Enjoy cracking the Cisco pesky passwords...
 *      (like 'enable password 7 104D000A0618')
 *
 * Passwords can be up to twenty-five mixed-case characters.
 * In the "encrypted" representation, the first two bytes of the long string are
 * a random decimal offset between 0 and 15 into a magic  block  of  characters,
 * and the remaining bytes are ascii-hex representations of the  password  bytes
 * xored against the character-block  bytes  from  the  given  offset  on  down,
 * modulus the character-block length.
 * The character block is "dsfd;kfoA,.iyewrkldJKDHSUB".
 *
 * compiled successfully with gcc version 2.95.3
 *      (gcc -Wall -W -Wstrict-prototypes -ansi -pedantic -O2 \
 *           -o cisco7crack cisco7crack.c)
 *
 * indented with the gnu-indent tool
 *      (indent -kr -i5 -nut cisco7crack.c)
 */

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "cisco7crack.h"


void usage(void)
{
     static const char *usage_msg[] = {
          "*** " PROGRAM " " VERSION,
          "    copyright (c) 2002 by " AUTHOR,
          "    the GNU GPLv2 applies to this program and code",
          "",
          "usage:",
          "   " PROGRAM " [-q] -c [-{a|#<0..15>}] <plaintext>",
          "   " PROGRAM " [-q] [-d] <ciphertext>",
          "   " PROGRAM " [-h]",
          "",
          "flags:    means:",
          "  -c        crypt <plaintext>",
          "  -a        display all the ways to crypt <plaintext>",
          "  -#<n>     display the n-th way to crypt <plaintext>",
          "  -d        decrypt <ciphertext> (default option)",
          "  -q        cause " PROGRAM " to be really quiet",
          "  -h        display this brief usage summary",
          "",
          "examples are:",
          "   " PROGRAM " -c#3 '@l1c3&b0b'",
          "   " PROGRAM " -c#3 -q n0v3rb0s3",
          "   " PROGRAM " 082F1C5A1A490D43000F5E033F78373B",
          "",
          "   a=`" PROGRAM " -cq b@shscr1pt`  # (bash shell)",
          "   [ $? -eq 0 ] && echo \"crypt: $a\" || echo \"error!\"",
          "",
          "enjoy cracking the Cisco IOS pesky passwords...",
          "for bugs and suggestions, please contact me by e-mail",
          ""
     };
     unsigned int i, u_lines = sizeof(usage_msg) / sizeof(*usage_msg);

     for (i = 0; i < u_lines; i++)
          fprintf(stderr, "%s\n", usage_msg[i]);
     exit(ERR_USAGE);
}

int decrypt_str(const char *passwd)
{
     char crypted[MAX_ENCRYPTED_LEN], *ptr1, *ptr2;
     unsigned int arglen, cryptlen, pairs, i, index = 0;

     if ((arglen = strlen(passwd)) > MAX_ENCRYPTED_LEN - 1)
          cfprintf(stderr, "WARNING: crypted string too long! "
                   "(last %d chars flushed)\n",
                   arglen - MAX_ENCRYPTED_LEN + 1);
     /* 'strncpy' used to avoid buffer overflow... */
     strncpy(crypted, passwd, MAX_ENCRYPTED_LEN);
     /* even if strlen(passwd) > MAXSTRLEN,
      * crypt[] must be a null terminated string
      */
     crypted[MAX_ENCRYPTED_LEN - 1] = 0;
     pairs = (cryptlen = strlen(crypted)) / 2;

     cfprintf(stdout, "%-17s: %s\n", "Encrypted string", crypted);
     cfprintf(stdout, "%-17s: ", "Plain string");

     ptr1 = strchr(dec, crypted[0]);
     ptr2 = strchr(dec, crypted[1]);
     if (!ptr1 || !ptr2) {
          /* 'crypted' should begin with two decimal digits */
          cfprintf(stderr,
                   "ERROR: illegal 1st pair of digits in crypted string\n");
          return ERR_INPUT_ILLEGAL_CHAR;
     }
     index = (ptr1 - dec) * 10 + (ptr2 - dec);

     for (i = 1; i < pairs; i++) {
          ptr1 = strchr(hex, crypted[i * 2]);
          ptr2 = strchr(hex, crypted[i * 2 + 1]);
          if (!ptr1 || !ptr2) {
               cfprintf(stderr,
                        "[?] ERROR: bad pair of hex digits (pair: %d)\n",
                        i + 1);
               return ERR_INPUT_ILLEGAL_CHAR;
          }
          printf("%c",
                 (((ptr1 - hex) << 4) + (ptr2 - hex)) ^ magic[index++]);
          index %= magic_size;
     }
     printf("\n");

     /* encrypted strings with odd number of digits are illegal */
     if (cryptlen % 2) {
          cfprintf(stderr,
                   "WARNING: input truncated! (odd number of letters)\n");
          return ERR_INPUT_ODD_DIGITS;
     }
     return ERR_NONE;
}

int crypt_str(const char *str2crypt, int xor_offset)
{
     register unsigned int i, j;
     unsigned int first, last, index, str2cryptlen = strlen(str2crypt);
     bool too_long_input;

     if ((too_long_input = (str2cryptlen > MAX_PLAIN_LEN))) {
          str2cryptlen = min(str2cryptlen, MAX_PLAIN_LEN);
          cfprintf(stderr, "WARNING: overly long password truncated after "
                   "%d characters\n", MAX_PLAIN_LEN);
          cfprintf(stdout, "%-17s: ", "Plain string");
          for (i = 0; i < MAX_PLAIN_LEN; i++)
               printf("%c", str2crypt[i]);
          printf("\n");
     } else
          cfprintf(stdout, "%-17s: %s\n", "Plain string", str2crypt);

     /* user ask for a random offset in magic[] */
     if (xor_offset == OFFSET_RANDOM)
          first = last = get_entropy();
     /* list all the crypted strings that IOS can generate */
     else if (xor_offset == OFFSET_ALL) {
          first = 0;
          last = MAX_XOR_OFFSET;
     }
     /* the user has specified an initial offset in magic[] */
     else
          first = last = xor_offset;

     cfprintf(stdout, "%-17s: ", "Encrypted string");

     /* from 'first' to 'last' way to crypt the 'str2crypt' */
     for (j = first; j <= last; j++) {
          /* mod just to make the code more robust */
          index = j % magic_size;
          if (j != first)
               cfprintf(stdout, "%-19s", "");
          printf("%02d", index);
          /* from first to last char allowed in 'str2crypt' */
          for (i = 0; i < str2cryptlen; i++) {
               printf("%02X", str2crypt[i] ^ magic[index++]);
               index %= magic_size;     /* mod : same as above */
          }
          printf("\n");
     }
     return too_long_input ? ERR_INPUT_TOO_LONG : ERR_NONE;
}

unsigned int get_entropy(void)
{
#ifdef LINUX
     int devurandom;
#endif
     unsigned int entropy;

#ifdef LINUX
     /* if your Linux system does not have /dev/random created already,
        it can be created with the following commands:
        mknod -m 644 /dev/urandom c 1 9
        chown root:root /dev/urandom
      */
     devurandom = open("/dev/urandom", O_RDONLY | O_NONBLOCK);
     if (devurandom != -1) {
          read(devurandom, &entropy, sizeof(entropy));
          close(devurandom);
     } else {
          /* rand() function call is not a very good source of randomness */
          cfprintf
              (stderr,
               "WARNING: couldn't open /dev/urandom, falling back to rand()\n");
#endif
          srand((unsigned int) time(NULL));
          /* to use higher-order bits of pseudo-random number... */
          entropy =
              (unsigned int) (1. * rand() * MAX_XOR_OFFSET / RAND_MAX);
#ifdef LINUX
     }
#endif
     return entropy;
}

void cfprintf(FILE * stream, const char *fmt, ...)
{                               /* conditional printf */
     va_list argptr;
     int cnt;

     if (opt.quiet)          /* no output message required */
          return;

     va_start(argptr, fmt);
     fflush(stdout);            /* to avoid some visualisation problems */
     cnt = vfprintf(stream, fmt, argptr);
     va_end(argptr);
}

#ifdef HEX_LOWER_SUPPORT
char *strtoupper(char *str)
{
     char *saved = str;

     while ((*str++ = toupper(*str)));
     return saved;
}
#endif

int main(int argc, char **argv)
{
     unsigned int c;
     opt.crypt = opt.decrypt = opt.quiet = false;
     opt.xor_offset = OFFSET_RANDOM;    /* random initial offset in magic[] */

     /* command line input parser */
     while (--argc > 0 && **++argv == '-') {
          /* catch user errors like : cisco7crack - -c#3 @l1c3 */
          if (!*(*argv + 1))
               usage();
          while ((c = *++*argv))        /* process multiple options like -sc#8 */
               switch (c) {
               case 'c':       /* crypt */
                    if (opt.decrypt)    /* decrypt option already selected */
                         usage();
                    opt.crypt = true;
                    break;
               case 'a':       /* display all the ways to crypt the input passwd */
                    if (opt.decrypt || opt.xor_offset != OFFSET_RANDOM)
                         usage();
                    opt.xor_offset = OFFSET_ALL;        /* all the offsets */
                    break;
               case '#':       /* user-defined initial offset in magic[] */
                    if (opt.decrypt || opt.xor_offset != OFFSET_RANDOM)
                         usage();
                    opt.xor_offset = atoi(*argv + 1);
                    if (opt.xor_offset < 0
                        || opt.xor_offset > MAX_XOR_OFFSET)
                         usage();
                    /* skip digits already parsed by atoi() */
                    while (isdigit(*(++*argv + 1)));
                    break;
               case 'd':       /* decrypt */
                    if (opt.crypt)
                         usage();
                    opt.decrypt = true;
                    break;
               case 'q':       /* minimize the program output */
                    opt.quiet = true;
                    break;
               case 'h':       /* help */
               default:        /* unknown option */
                    usage();
               }
     }

     if (argc != 1)
          usage();              /* usage error (too many arguments entered) */

     if (!opt.crypt && !opt.decrypt) {  /* make decrypt the default actions */
          if (opt.xor_offset != OFFSET_RANDOM)
               usage();
          opt.decrypt = true;
     }

     return opt.decrypt ?
#ifdef HEX_LOWER_SUPPORT
         decrypt_str(strtoupper(*argv))
#else
         decrypt_str(*argv)
#endif
         : crypt_str(*argv, opt.xor_offset);
}
