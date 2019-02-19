section .rodata

fmt02x db "%02x", 00

fmtd db "%d", 00
fmtx db "%x", 00

tokbase db "ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadFN2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZzI2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO", 00

vjavalangstring db "()Ljava/lang/String;", 00
getpkgname db "getPackageName", 00


section .text

extern sprintf
extern strlen
extern strcat
extern strcmp
extern memcpy
extern time

extern BE
extern BEL
extern BD
extern BDL

extern MI
extern MU
extern MF

extern __stack_chk_fail_local

global r

global be
global bd

global me

global Java_com_coolapk_market_util_AuthUtils_getAS

%define bytesz  0x1
%define charsz  0x1
%define wordsz  0x4
%define intsz   0x4
%define dwordsz 0x8

%macro frame 1
    push ebp
    mov ebp, esp
    lea esp, [esp-%1]
%endmacro

%macro just_unwind 1
    lea esp, [esp+%1]
    pop ebp
%endmacro

%macro unwind 1
    lea esp, [esp+%1]
    pop ebp
    ret
%endmacro

%define suba1w [esp]
%define suba2w [esp+intsz]
%define suba3w [esp+intsz*2]
%define suba4w [esp+intsz*3]

%define suba1d [esp]
%define suba2d [esp+intsz]
%define suba3d [esp+intsz*2]
%define suba4d [esp+intsz*3]

%define arg(n)    dword [ebp+intsz+intsz*n]
%define local(n)  dword [ebp-intsz*n]
%define speciallocal(n) [ebp-intsz*n]
%define localoffset(off) [ebp-off]
%define locals(n) (intsz*n)
%define subcalls(n) (intsz*n)
%define local_m_with_subcall_n_max(m, n, max) (intsz*max)

__x86_get_pc_thunk_bx:
    mov ebx, dword [esp]
    ret

;; ========== FUNCTION r ==========
;; Line 13
;; char *arg1 (s) @ fbx+0

;; int   len  (length) @ fbx-24, L15
;; int   i(-32, L16), j(-28, L16), c(-20, L16)
%define r_arg1 arg(1)

%define r_len  local(1)
%define r_j    local(2)
%define r_i    local(3)
%define r_c    local(4)

%define r_framesz locals(4)
r:
    frame r_framesz

    mov eax, r_arg1
    mov suba1d, eax
    call strlen
    mov r_len, eax

    mov r_i, 0

    mov eax, r_len
    sub eax, 1
    mov r_j, eax

    jmp r_forloop_branch
r_forloop:
    mov edx, r_i
    mov eax, r_arg1
    add eax, edx

    movzx eax, byte [eax]
    movsx eax, al

    mov r_c, eax

    mov edx, r_i
    mov eax, r_arg1
    add edx, eax

    mov ecx, r_j
    mov eax, r_arg1
    add eax, ecx

    movzx eax, byte [eax]
    mov byte [edx], al

    mov edx, r_j
    mov eax, r_arg1
    add eax, edx

    mov edx, r_c
    mov byte [eax], dl

    add r_i, 1
    sub r_j, 1

r_forloop_branch:
    mov eax, r_i
    cmp eax, r_j
    jl r_forloop

    unwind r_framesz



;; ========== FUNCTION bd ==========
;; Line 27
;; char *arg1 (dst) @ fbx+0
;; char *arg2 (src) @ fbx+4
%define bd_arg1 arg(1)
%define bd_arg2 arg(2)

%define bd_framesz subcalls(2)
bd:
    frame bd_framesz

    mov eax, bd_arg2
    mov suba2d, eax
    mov eax, bd_arg1
    mov suba1d, eax
    call BD

    unwind bd_framesz



;; ========== FUNCTION be ==========
;; Line 47
;; char *arg1 (dst) @ fbx+0
;; char *arg2 (src) @ fbx+4

;; int  src_len @ fbx-20, L49
%define be_arg1    arg(1)
%define be_arg2    arg(2)
%define be_src_len local(1)

%define be_framesz local_m_with_subcall_n_max(1, 3, 4)
be:
    frame be_framesz

    mov eax, be_arg2
    mov suba1d, eax
    call strlen
    mov be_src_len, eax

    mov eax, be_src_len
    mov suba3d, eax

    mov eax, be_arg2
    mov suba2d, eax

    mov eax, be_arg1
    mov suba1d, eax
    call BE

    unwind be_framesz



;; ========== FUNCTION me ==========
;; Line 33
;; char *arg1 (dst) @ fbx-196
;; char *arg2 (src) @ fbx-200

;; unsigend char *digest[16] @ fbx-188, L35
;; MD5_CTX @ fbx-172, L36
;; int i @ fbx-192, L41
%define me_arg1 arg(1)
%define me_arg2 arg(2)

; (3)|....| (2)|....| (1)|....| <ebp>
%define me_input_str  local(1)
%define me_output_buf local(2)
%define me_i          local(3)

; (7) [....|....|....|....] (3)|....| (2)|....| (1)|....| <ebp>
%define me_digest_s16  speciallocal(7)

%define MD5_CTXsz (0x58+(intsz*16))
; [.{sizeof(MD5_CTX)}] (7) [....|....|....|....] (3)|....| (2)|....| (1)|....| <ebp>
%define me_offset_md5 (intsz*7+MD5_CTXsz)
%define me_md5_context localoffset(me_offset_md5)

%define me_framesz local_m_with_subcall_n_max(me_offset_md5, (3*intsz), (me_offset_md5+3*intsz))
me:
    frame me_framesz

    mov eax, me_arg1
    mov me_output_buf, eax
    mov eax, me_arg2
    mov me_input_str, eax

    lea eax, me_md5_context
    mov suba1d, eax
    call MI

    mov eax, me_input_str
    mov suba1d, eax
    call strlen

    mov suba3d, eax
    mov eax, me_input_str
    mov suba2d, eax
    lea eax, me_md5_context
    mov suba1d, eax
    call MU

    lea eax, me_md5_context
    mov suba2d, eax
    lea eax, me_digest_s16
    mov suba1d, eax
    call MF

    mov me_i, 0
    jmp me_for_loop_branch
me_for_loop:
    lea edx, me_digest_s16
    mov eax, me_i
    add eax, edx

    movzx eax, byte [eax]
    movzx eax, al

    mov edx, me_i
    add edx, edx
    mov ecx, edx

    mov edx, me_output_buf
    add edx, ecx

    mov suba3d, eax
    mov eax, fmt02x
    mov suba2d, eax
    mov suba1d, edx
    call sprintf

    add me_i, 1
me_for_loop_branch:
    cmp me_i, 15
    jle me_for_loop

    unwind me_framesz



;; Begin REAL Reversing

;; ========== FUNCTION Java_com_coolapk_market_util_AuthUtils_getAS ==========
;; Line 53
;; result jstring

;; FBREG  TYPE        NAME         OFFSET
;; (-436) JNIEnv     *env          [ebp+0x8]
;; (-440) jobject     obj          [ebp+0xc]
;; (-444) jobject     entryObject  [ebp+0x10]
;; (-448) jstring     jstr         [ebp+0x14]
%define ga_jnienv [ebp+0x8]
%define alt_jnienv [ebp-0x1ac]

%define ga_jniobj [ebp+0xc]
%define alt_jniobj [ebp-0x1b0]

%define ga_jnientryobj [ebp+0x10]
%define alt_entryobj [ebp-0x1b4]

%define ga_uuid [ebp+0x14]
%define alt_uuid [ebp-0x1b8]

;; LINE  FBREG     TYPE         NAME                     OFFSET
;; L55   (-432)    jclass       android_content_Context  [ebp-0x1a8]
;; L56   (-428)    jmethodID    midGetPackageName        [ebp-0x1a4]
;; L60   (-424)    jstring      packageName              [ebp-0x1a0]
;; L61   (-420)    char         *nPackageName            [ebp-0x19c]
;; L63   (-314)    char         cp[]                     [ebp-0x132]
;; L73   (-229)    char         h[]                      [ebp-0xdd]
;; L74   (-295)    char         mt[]                     [ebp-0x11f]
;; L80   (-416)    int          h2_len                   [ebp-0x198]
;; L81  *(-408)    char         h2[]                     [ebp-0x190]
;; L88   (-404)    int          h3_len                   [ebp-0x18c]
;; L89  *(-396)    char         h3[]                     [ebp-0x184]
;; L94   (-392)    int          h4_len                   [ebp-0x180]
;; L95  *(-384)    char         h4[]                     [ebp-0x178]
;; L101  (-380)    char         *di                      [ebp-0x174]
;; L103  (-325)    char         st[]                     [ebp-0x13d]
;; L104  (-376)    int          it                       [ebp-0x170]
;; L108  (-335)    char         ht[]                     [ebp-0x147]
;; L115  (-372)    int          tl                       [ebp-0x16c]
;; L116 *(-364)    char         t[]                      [ebp-0x164]
;; L127  (-360)    int          tbl                      [ebp-0x160]
;; L128 *(-352)    char         tb[]                     [ebp-0x158]
;; L131  (-262)    char         aa[]                     [ebp-0xfe]
;; L134  (-348)    int          str_len                  [ebp-0x154]
;; L135 *(-340)    char         str[]                    [ebp-0x14c]


%define android_content_Context  [ebp-0x1a8]
%define midGetPackageName        [ebp-0x1a4]
%define packageName              [ebp-0x1a0]
%define pnPackageName            [ebp-0x19c]
%define cps                      [ebp-0x132]
%define hs                       [ebp-0xdd]
%define mts                      [ebp-0x11f]
%define h2_len                   [ebp-0x198]
%define h2s                      [ebp-0x190]
%define h3_len                   [ebp-0x18c]
%define h3s                      [ebp-0x184]
%define h4_len                   [ebp-0x180]
%define h4s                      [ebp-0x178]
%define pdi                      [ebp-0x174]
%define sts                      [ebp-0x13d]
%define it                       [ebp-0x170]
%define hts                      [ebp-0x147]
%define tl                       [ebp-0x16c]
%define ts                       [ebp-0x164]
%define tbl                      [ebp-0x160]
%define tbs                      [ebp-0x158]
%define aas                      [ebp-0xfe]
%define str_len                  [ebp-0x154]
%define strs                     [ebp-0x14c]

%define tokbase_gcc_move         [ebp - 0x1BC]

;; Initial frame size (dynamic allocation required)
%define ga_framesz 0

Java_com_coolapk_market_util_AuthUtils_getAS:
    push edi
    push esi

    frame ga_framesz

;; rodata offset calculating code omitted
;; stack protector code omitted


;; Setup alt variables
    mov eax, ga_jnienv
    mov alt_jnienv, eax

    mov eax, ga_jniobj
    mov alt_jniobj, eax

    mov eax, ga_jnientryobj
    mov alt_entryobj, eax

    mov eax, ga_uuid
    mov alt_uuid, eax
;; done

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax+0x7c]

;; jclass (*GetObjectClass)(JNIEnv *, jobject); (+0x7c)

    mov edx, alt_entryobj
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

    mov android_content_Context, eax

; android_content_Context = (*env)->GetObjectClass(env, entryObject);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 84]

;; jmethodID (*GetMethodID)(JNIEnv *, jclass, char *name, char *sig); (+0x84)

    mov edx, vjavalangstring
    mov suba4d, edx
    mov edx, getpkgname
    mov suba3d, edx
    mov edx, android_content_Context
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

    mov midGetPackageName, eax

; midGetPackageName = (*env)->GetMethodID(env, android_content_Context, "()Ljava/lang/String;", "getPackageName");


    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 88]

;; jobject (*CallObjectMethod)(JNIEnv *, jobject, jmethodID); (+0x88)

    mov edx, midGetPackageName
    mov suba3d, edx
    mov edx, alt_entryobj
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax
    mov packageName, eax

; packageName = (*env)->CallObjectMethod(env, entryObject, midGetPackageName);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, dword [eax + 0x2a4]

;; char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *); (+0x2a4)

    mov suba3d, dword 0
    mov edx, packageName
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax
    mov pnPackageName, eax

; nPackageName = env->GetStringUTFChars(env, packageName, 0);

    mov dword cps, "com."
    mov dword [ebp - 0x12E], "cool"
    mov dword [ebp - 0x12A], "apk."
    mov dword [ebp - 126], "mark"
    mov word [ebp - 122], "et"
    mov byte [ebp - 120], 00
    lea eax, cps

;; "com.coolapk.market\00"

    mov suba2d, eax
    mov eax, pnPackageName
    mov suba1d, eax
    call strcmp
    test eax, eax

    je ga_continue_tokengen

; if (strcmp(nPackageName, "com.coolapk.market") == 1) {
    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 0x5C]

;; void (*DeleteLocalRef)(JNIEnv *, jobject); (+0x5c)

    mov edx, android_content_Context
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

; (*env)->DeleteLocalRef(env, android_content_Context);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 0x2a8]

;; void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); (+0x2a8)

    mov edx, pnPackageName
    mov [esp + 8], edx
    mov edx, packageName
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

; (*env)->ReleaseStringUTFChars(env, packageName, nPackageName);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 54]

;; jobject (*NewGlobalRef)(JNIEnv *, jobject); (+0x54)

    mov dword suba2d, 0
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax
    jmp ga_exit

; return (*env)->NewGlobalRef(env, NULL);
; }

; with a new soul~ :P
ga_continue_tokengen:
    lea eax, hs
    mov edx, tokbase
    mov dword tokbase_gcc_move, 0xC1

;; 0xC1 = 193, sizeof(tokbase) = 193

    mov ecx, eax
    and ecx, 1
    test ecx, ecx
    je ga_tokbase_mv1
    movzx ecx, byte [edx]
    mov byte [eax], cl
    lea eax, [eax + 1]
    lea edx, [edx + 1]
    sub dword tokbase_gcc_move, 1
ga_tokbase_mv1:
    mov ecx, eax
    and ecx, 2
    test ecx, ecx
    je ga_tokbase_mv2
    movzx ecx, word [edx]
    mov [eax], cx
    lea eax, [eax + 2]
    lea edx, [edx + 2]
    sub dword tokbase_gcc_move, 2
ga_tokbase_mv2:
    mov ecx, tokbase_gcc_move
    shr ecx, 2
    mov edi, eax
    mov esi, edx
;   rep movsd dword es:[edi], dword ds:[esi] ; TODO
    rep movsd
    mov edx, esi
    mov eax, edi
    mov ecx, 0
    mov esi, tokbase_gcc_move
    and esi, 2
    test esi, esi
    je ga_tokbase_mv3
    movzx esi, word [edx + ecx]
    mov [eax + ecx], si
    add ecx, 2
ga_tokbase_mv3:
    mov esi, tokbase_gcc_move
    and esi, 1
    test esi, esi
    je ga_tokbase_moved
    movzx edx, byte [edx + ecx]
    mov [eax + ecx], dl

ga_tokbase_moved:
    lea eax, hs
    mov suba1d, eax
    call r

; char h[] = "ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadFN2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZzI2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO";
; r(h);

    lea eax, hs
    mov suba1d, eax
    call BDL
    mov h2_len, eax

; h2_len = BDL(h);

    mov eax, h2_len
    lea edx, [eax - 1]
    mov [ebp-194], edx
    mov edx, eax
    mov eax, 10
    sub eax, 1
    add eax, edx
    mov edi, 10
    mov edx, 0
    div edi
    imul eax, eax, 10
    sub esp, eax
    lea eax, [esp + 10]
    add eax, 0
    mov h2s, eax

; char h2[h2_len];

    mov eax, h2s
    lea edx, hs
    mov suba2d, edx
    mov suba1d, eax
    call bd

; bd(h2, h);

    mov eax, h2s
    mov suba1d, eax
    call r

; r(h2);

    mov eax, h2s
    mov suba1d, eax
    call strlen
    sub eax, 40
    mov h3_len, eax

; int h3_len = strlen(h2) - 40;

    mov eax, h3_len
    add eax, 1
    lea edx, [eax - 1]
    mov [ebp-188], edx
    mov edx, eax
    mov eax, 10
    sub eax, 1
    add eax, edx
    mov edi, 10
    mov edx, 0
    div edi
    imul eax, eax, 10
    sub esp, eax
    lea eax, [esp + 10]
    add eax, 0
    mov h3s, eax

; char h3[h3_len];

    mov edx, h3_len
    mov eax, h2s
    lea ecx, [eax + 20]
    mov eax, h3s
    mov suba3d, edx
    mov suba2d, ecx
    mov suba1d, eax
    call memcpy

; memcpy(h3, h2 + 0x20, h3_len);

    mov edx, h3s
    mov eax, h3_len
    add eax, edx
    mov byte [eax], 0

; h3[h3_len] = 0

    mov eax, h3s
    mov suba1d, eax
    call BDL

    mov h4_len, eax

; h4_len = BDL(h3);

    mov eax, h4_len
    lea edx, [eax - 1]
    mov [ebp - 0x17C], edx
    mov edx, eax
    mov eax, 10
    sub eax, 1
    add eax, edx
    mov edi, 10
    mov edx, 0
    div edi
    imul eax, eax, 10
    sub esp, eax
    lea eax, [esp + 10]
    add eax, 0
    mov h4s, eax

; char h4[h4_len];

    mov edx, h3s
    mov eax, h4s
    mov suba2d, edx
    mov suba1d, eax
    call bd

; bd(h4, h3);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 0x2a4]

;; char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *); (+0x2a4)

    mov suba3d, dword 0
    mov edx, alt_uuid
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax
    mov pdi, eax

; char *di = (*env)->GetStringUTFChars(env, str, 0);

    mov suba1d, dword 0
    call time
    mov it, eax

; int it = time(NULL);

    mov eax, it
    mov suba3d, eax
    mov eax, fmtd
    mov suba2d, eax
    lea eax, sts
    mov suba1d, eax
    call sprintf

; sprintf(st, "%d", it);

    mov eax, it
    mov suba3d, eax
    mov eax, fmtx
    mov suba2d, eax
    lea eax, hts
    mov suba1d, eax
    call sprintf

; sprinf(ht, "%x", it);

    lea eax, sts
    mov suba2d, eax
    lea eax, mts
    mov suba1d, eax
    call me

; me(mt, st);

    mov eax, h4s
    mov suba1d, eax
    call strlen
    mov esi, eax

;; $si = strlen(h4);

    mov eax, pdi
    mov suba1d, eax
    call strlen
    add esi, eax

;; $si += strlen(di);

    mov eax, pnPackageName
    mov suba1d, eax
    call strlen
    add eax, esi

;; $ax = $si + strlen(pnPackageName);

    add eax, 0x23

;; $ax += 0x23

    mov tl, eax

; int tl = strlen(pnPackageName) + strlen(di) + strlen(h4) + 0x23

    mov eax, tl
    lea edx, [eax - 1]
    mov [ebp - 168], edx
    mov edx, eax
    mov eax, 10
    sub eax, 1
    add eax, edx
    mov edi, 10
    mov edx, 0
    div edi
    imul eax, eax, 10
    sub esp, eax
    lea eax, [esp + 10]
    add eax, 0
    mov ts, eax

; char t[tl];

    mov edx, h4s
    mov eax, ts
    mov suba2d, edx
    mov suba1d, eax
    call strcat

; strcat(t, h4);

    mov eax, ts
    lea edx, mts
    mov suba2d, edx
    mov suba1d, eax
    call strcat

; strcat(t, mt);

    mov esi, ts
    mov eax, ts
    mov ecx, 0xFFFFFFFF
    mov edx, eax
    mov eax, 0
    mov edi, edx
;   repne scasb al, byte [edi] ; TODO
    repne scasb
    mov eax, ecx
    not eax
    sub eax, 1
    add eax, esi
    mov word [eax], 24 ; '$'

; ...
; // t = t + "$"

    mov eax, ts
    mov edx, pdi
    mov suba2d, edx
    mov suba1d, eax
    call strcat

; strcat(di, t);

    mov esi, ts
    mov eax, ts
    mov ecx, 0xFFFFFFFF
    mov edx, eax
    mov eax, 0
    mov edi, edx
;   repne scasb al, byte [edi] ; TODO
    repne scasb
    mov eax, ecx
    not eax
    sub eax, 1
    add eax, esi
    mov word [eax], 26 ; '&'

; ...
; // t = t + "&"

    mov eax, ts
    mov edx, pnPackageName
    mov suba2d, edx
    mov suba1d, eax
    call strcat

; strcat(t, nPackageName);

    mov eax, tl
    mov suba1d, eax
    call BEL
    mov tbl, eax

; int tbl = BEL(t);

    mov eax, tbl
    lea edx, [eax - 1]
    mov [ebp - 0x15C], edx
    mov edx, eax
    mov eax, 10
    sub eax, 1
    add eax, edx
    mov edi, 10
    mov edx, 0
    div edi
    imul eax, eax, 10
    sub esp, eax
    lea eax, [esp + 10]
    add eax, 0
    mov tbs, eax

; char tb[tbl];

    mov edx, ts
    mov eax, tbs
    mov suba2d, edx
    mov suba1d, eax
    call be

; be(tb, t);

    mov eax, tbs
    mov suba2d, eax
    lea eax, aas
    mov suba1d, eax
    call me

; me(aa, tb);

    lea eax, aas
    mov suba1d, eax
    call strlen
    mov esi, eax

;; $si = strlen(aa);

    mov eax, pdi
    mov suba1d, eax
    call strlen
    add esi, eax

;; $si += strlen(di);

    lea eax, hts
    mov suba1d, eax
    call strlen
    add eax, esi
    add eax, 2
    mov str_len, eax

; int str_len = strlen(aa) + strlen(di) + strlen(hts) + 2;

    mov eax, str_len
    lea edx, [eax - 1]
    mov [ebp - 150], edx
    mov edx, eax
    mov eax, 10
    sub eax, 1
    add eax, edx
    mov edi, 10
    mov edx, 0
    div edi
    imul eax, eax, 10
    sub esp, eax
    lea eax, [esp + 10]
    add eax, 0
    mov strs, eax

; char str[str_len];

    mov eax, strs
    lea edx, aas
    mov suba2d, edx
    mov suba1d, eax
    call strcat

; strcat(str, aa);

    mov eax, strs
    mov edx, pdi
    mov suba2d, edx
    mov suba1d, eax
    call strcat

; strcat(str, di);

    mov esi, strs
    mov eax, strs
    mov ecx, 0xFFFFFFFF
    mov edx, eax
    mov eax, 0
    mov edi, edx
;   repne scasb al, byte [edi] ; TODO
    repne scasb
    mov eax, ecx
    not eax
    sub eax, 1
    add eax, esi
    mov word [eax], 7830  ; '0x'
    mov byte [eax + 2], 0 ; "\00"

; ...
; // str = str + "0x"

    mov eax, strs
    lea edx, hts
    mov suba2d, edx
    mov suba1d, eax
    call strcat

; strcat(str, ht);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 0x2a8]

;; void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); (+0x2a8)

    mov edx, pdi
    mov [esp + 8], edx
    mov edx, alt_uuid
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

; (*env)->ReleaseStringUTFChars(env, jstr, di);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 0x5C]

;; void (*DeleteLocalRef)(JNIEnv *, jobject); (+0x5c)

    mov edx, android_content_Context
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

; (*env)->DeleteLocalRef(env, android_content_Context);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 0x2a8]

;; void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); (+0x2a8)

    mov edx, pnPackageName
    mov suba2d, edx
    mov edx, packageName
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

; (*env)->ReleaseStringUTFChars(env, packageName, nPackageName);

    mov eax, alt_jnienv
    mov eax, [eax]
    mov eax, [eax + 0x29c]

;; jstring (*NewStringUTF)(JNIEnv *, char *); (+0x29c)

    mov edx, strs
    mov suba2d, edx
    mov edx, alt_jnienv
    mov suba1d, edx
    call eax

; (*env)->NewStringUTF(env, strs);

    nop

ga_exit:

    just_unwind ga_framesz

    pop esi
    pop edi

    ret
