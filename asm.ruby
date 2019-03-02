#!/usr/bin/env ruby -d
# Don't be evil

require 'digest'
require 'base64'
require 'uuid'

CoolLibrary = Module.new

# CoolApk client token computing library
module CoolLibrary
    # CoolApk package name
    Coolapk = "com.coolapk.market"
    # Hex format string
    Fmtx = "%x"
    # 2 hex digit format string
    Fmt02x = "%02x"
    # Decimal format string
    Fmtd = "%d"

    # Token base constant
    Tokbase = "ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadF" \
              "N2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8" \
              "EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZz" \
              "I2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO"
end

# Generating Algorithm reverse-engineering from CoolApk Android v8 x86 liba.so code
# Date: 2019.2.14-2019.2.20
# With radare2 & dwarview & VSCode & NASM
class << CoolLibrary
    # String reverse
    def r(s); s.reverse; end

    # Base64 decode
    def bd(src)
        Base64.decode64(src)
    end
    
    # Base64 encode
    def be(src)
        Base64.encode64(src)
    end
    
    # MD5 message digest
    def me(src)
        digest = String.new
    
        md5 = Digest::MD5.new
        md5 << src
    
        15.times do |n|
            digest[n * 2] = format(CoolLibrary::Fmt02x, md5.digest.bytes[n])
        end
    
        # alt. return md5.hexdigest
        digest
    end

    # Print debug compution information
    def cv(name, val)
        if $DEBUG
            print "Computed #{name} as "
            puts val
        end
    end
end

# Token generation algorithm

# ========== FUNCTION Java_com_coolapk_market_util_AuthUtils_getAS ==========
# Line 53
# result jstring
#
# FBREG  TYPE        NAME         OFFSET
# (-436) JNIEnv     *env          [ebp+0x8]
# (-440) jobject     obj          [ebp+0xc]
# (-444) jobject     entryObject  [ebp+0x10]
# (-448) jstring     jstr         [ebp+0x14]

# LINE  FBREG     TYPE         NAME                     OFFSET
# L55   (-432)    jclass       android_content_Context  [ebp-0x1a8]
# L56   (-428)    jmethodID    midGetPackageName        [ebp-0x1a4]
# L60   (-424)    jstring      packageName              [ebp-0x1a0]
# L61   (-420)    char         *nPackageName            [ebp-0x19c]
# L63   (-314)    char         cp[]                     [ebp-0x132]
# L73   (-229)    char         h[]                      [ebp-0xdd]
# L74   (-295)    char         mt[]                     [ebp-0x11f]
# L80   (-416)    int          h2_len                   [ebp-0x198]
# L81  *(-408)    char         h2[]                     [ebp-0x190]
# L88   (-404)    int          h3_len                   [ebp-0x18c]
# L89  *(-396)    char         h3[]                     [ebp-0x184]
# L94   (-392)    int          h4_len                   [ebp-0x180]
# L95  *(-384)    char         h4[]                     [ebp-0x178]
# L101  (-380)    char         *di                      [ebp-0x174]
# L103  (-325)    char         st[]                     [ebp-0x13d]
# L104  (-376)    int          it                       [ebp-0x170]
# L108  (-335)    char         ht[]                     [ebp-0x147]
# L115  (-372)    int          tl                       [ebp-0x16c]
# L116 *(-364)    char         t[]                      [ebp-0x164]
# L127  (-360)    int          tbl                      [ebp-0x160]
# L128 *(-352)    char         tb[]                     [ebp-0x158]
# L131  (-262)    char         aa[]                     [ebp-0xfe]
# L134  (-348)    int          str_len                  [ebp-0x154]
# L135 *(-340)    char         str[]                    [ebp-0x14c]
def CoolLibrary.getAS(uuid = UUID.new.generate, now = Time.new)
    cv("UUID", uuid)
    cv("Time", now)

    package_name = CoolLibrary::Coolapk

    cv("Package name", package_name)

    # asm.s:591
    h = CoolLibrary::Tokbase
    h = r(h)
    cv("Reverse security", h)

    h2 = bd(h)

    h2 = r(h2)

    cv("H2", h2)

    h3_len = h2.size - 0x40 - 0x1 # valid chars -32

    h3 = h2[0x20..h3_len+0x20]
    cv("H3", h3)



    h4 = bd(h3)
    cv("H4", h4)

    di = uuid
    it = now.to_i

    st = format(CoolLibrary::Fmtd, it)
    ht = format(CoolLibrary::Fmtx, it)

    mt = me(st)
    cv("MD5SUM(time.to_i)", mt)

    tl = package_name.size + di.size + h4.size + 0x23 - 0x1

    cv("Token checkum size", tl)

    t = StringIO.new

    t << h4 << mt << "$"
    di += t.string
    t << "&" << package_name
    t = t.string

    cv("Token check sum", t)
    tb = be(t)
    cv("Token base64", tb)

    aa = me(tb)
    cv("Token base64 MD5SUM", aa)

    str_len = aa.size + di.size + ht.size + 2 - 0x1;
    cv("Final token size", str_len)

    str = StringIO.new
    str << aa << di << "0x" << ht

    str = str.string

    cv("token", str)

    return str
end

CoolLibrary.getAS if $PROGRAM_NAME == __FILE__
