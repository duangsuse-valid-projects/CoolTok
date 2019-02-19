// 002 0x00000000 0x00000000  LOCAL   FILE    0 b.c
#pragma once

/* From coolapk 8.8.3 liba.so (With DWARF debug information) */
/* Reverse engineering by duangsuse @ 2019.2.17 */

/* Source code: https://svn.apache.org/repos/asf/apr/apr/trunk/encoding/apr_base64.c */
/* See also: https://github.com/mllg/base64url/blob/master/src/base64.c */

// 003 0x00002500 0x00002500  LOCAL    OBJ  256 pr2six
static const unsigned char pr2six[256];
// 004 0x00002600 0x00002600  LOCAL    OBJ   65 b6
static const char b6[64 + /* C EOS */ 1];

// 004 0x000006a4 0x000006a4 GLOBAL   FUNC   96 BDL
// CoolLibrary/app/src/main/jni/b.c:112-125
int BDL(const char *bufcoded);

// 005 0x00000704 0x00000704 GLOBAL   FUNC  477 BD
// CoolLibrary/app/src/main/jni/b.c:128-171
// Base64decode
int BD(char *bufplain, const char *bufcoded);

// 006 0x000008e1 0x000008e1 GLOBAL   FUNC   35 BEL
// CoolLibrary/app/src/main/jni/b.c:178-181
// Base64encode_len
int BEL(int len);

// 007 0x00000904 0x00000904 GLOBAL   FUNC  546 BE
// CoolLibrary/app/src/main/jni/b.c:184-214
// Base64encode
int BE(char *encoded, const char *string, int len);
