// 005 0x00000000 0x00000000  LOCAL   FILE    0 m.c
#pragma once

/* From coolapk 8.8.3 liba.so (With DWARF debug information) */
/* Reverse engineering by duangsuse @ 2019.2.17 */

#include <stdint.h>

typedef uint32_t MD5_u32plus;

/* Basetype: sizetype */
/* Basetype: unsigned char */
typedef struct
{
    MD5_u32plus lo /* +0x0 */, hi;                            /* +0x4 */
    MD5_u32plus a /* +0x8 */, b /* +0xc */, c /* +0x10 */, d; /* +0x14 */
    unsigned char buffer[64];                                 /* +0x18 */
    MD5_u32plus block[16];                                    /* +0x58 */
} MD5_CTX;

/* Source file at https://github.com/boostorg/uuid/blob/405f9614312bb6d6d703d3b932f45bd7cb3b1a1e/include/boost/uuid/detail/md5.hpp */

// 006 0x00000b2a 0x00000b2a  LOCAL   FUNC 3088 body
// From module:   /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/m.c
// Address range: 0xb2a - 0xc0e
// Line range:    93 - 116
/* char *body(int32_t ctx, char *data, int32_t size); */
const void *body(MD5_CTX *ctx, const void *data, unsigned long int size);

// 011 0x000018be 0x000018be GLOBAL   FUNC  649 MF
/* MD5_Final */
// From module:   /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/m.c
// Address range: 0x18be - 0x1b47
// Line range:    248 - 297
/* void MF(char *result, int32_t ctx); */
void MF(unsigned char *result, MD5_CTX *ctx);

// 008 0x0000173a 0x0000173a GLOBAL   FUNC   64 MI
/* MD5_Init */
// From module:   /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/m.c
// Address range: 0x173a - 0x177a
// Line range:    201 - 210
/* void MI(int32_t ctx); */
void MI(MD5_CTX *ctx);

// 009 0x0000177a 0x0000177a GLOBAL   FUNC  324 MU
/* MD5_Update */
// From module:   /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/m.c
// Address range: 0x177a - 0x18be
// Line range:    213 - 245
/* void MU(int32_t ctx, char *data, uint32_t size); */
void MU(MD5_CTX *ctx, const void *data, unsigned long int size);
