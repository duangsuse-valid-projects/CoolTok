// 007 0x00000000 0x00000000  LOCAL   FILE    0 a.c
#pragma once

/* From coolapk 8.8.3 liba.so (With DWARF debug information) */
/* Reverse engineering by duangsuse @ 2019.2.17 */

#include "ca_jni.h"

#include "md5_digest.h"
#include "base64.h"

// 020 0x00001d2a 0x00001d2a GLOBAL   FUNC 1988 Java_com_coolapk_market_util_AuthUtils_getAS
// CoolLibrary/app/src/main/jni/a.c:53-145
/* char *Java_com_coolapk_market_util_AuthUtils_getAS(size_t env, char *obj, char *entryObject, char *jstr); */
jstring Java_com_coolapk_market_util_AuthUtils_getAS(JNIEnv *env, jobject obj, jobject entryObject, jstring jstr);

// 015 0x00001bc4 0x00001bc4 GLOBAL   FUNC   44 bd
// CoolLibrary/app/src/main/jni/a.c:27-30
// b64d like wrapper
// bd(dst, src)
void bd(char *out, const char *code_str);

// 019 0x00001ce9 0x00001ce9 GLOBAL   FUNC   65 be
// CoolLibrary/app/src/main/jni/a.c:47-51
// b64e like wrapper
// bd(dst, src)/src_len
void be(char *dst, const char *src);

// 016 0x00001bf0 0x00001bf0 GLOBAL   FUNC  249 me
// CoolLibrary/app/src/main/jni/a.c:33-44
void me(char *dst, const char *src);

// 013 0x00001b47 0x00001b47 GLOBAL   FUNC  125 r
// CoolLibrary/app/src/main/jni/a.c:13-24
// r(s)/int length/int c/int i/int j
void r(char *s);
