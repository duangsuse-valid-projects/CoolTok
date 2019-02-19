#!/usr/bin/env ruby -d

require 'digest'
require 'base64'
require 'uuid'

def r(s); s.reverse; end

def bd(src)
    Base64.decode64(src)
end

def be(src)
    Base64.encode64(src)
end

def me(src)
    digest = String.new

    md5 = Digest::MD5.new
    md5 << src

    15.times do |n|
        digest[n * 2] = format("%02x", md5.digest.bytes[n])
    end

    # alt. return md5.hexdigest
    digest
end

Coolapk = "com.coolapk.market"
Tokbase = "ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadFN2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZzI2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO"

Fmtx = "%x"

def cv(name, val)
    if $DEBUG
        print "Computed #{name} as "
        puts val
    end
end

def getAS(uuid = UUID.new.generate, now = Time.new)
    cv("UUID", uuid)
    cv("Time", now)
    cv("Package name", Coolapk)

    h = r(Tokbase)
    cv("Reverse security", h)
end

getAS if $PROGRAM_NAME == __FILE__
