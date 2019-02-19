#include <stdio.h>
#include <string.h>
#include <time.h>

#include "include/coolapk.h"

/* Reverse engineering by duangsuse using Radare2 / dwarview / dwarf_to_c
  radare2 3.3.0-git 21045 @ linux-x86-64 git.3.2.1-366-ga795cd647
  commit: a795cd647c64028137f77f0ad78719d768f7292a build: 2019-02-16__15:16:12 */

void r(char *s)                  // L13
{                                // L14
    int length = (int)strlen(s); // L15
    int c, i, j;                 // L16

    for (i = 0, j = length - 1; i < j; i++) // L18
    {
        c = s[i];       // L20
        s[i] = s[j];    // L21
        s[j] = (char)c; // L22
        j--;
    } // L24
}

void bd(char *dst, const char *src) // L27
{
    BD(dst, src);
}

void me(char *dst, const char *src) // L33
{
    unsigned char digest[16]; // L35
    MD5_CTX context;          // L36
    MI(&context);
    MU(&context, src, strlen(src));
    MF(digest, &context);

    for (int i = 0; i <= 15; i++)
    {
        sprintf((dst + (i * 2)), "%02x", digest[i]);
    }
}

void be(char *dst, const char *src) // L47
{
    int src_len = (int)strlen(src);

    BE(dst, src, src_len);
}
