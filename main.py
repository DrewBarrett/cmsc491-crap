#!/usr/bin/env python3

def pstring(instr):
    toret = instr.encode("utf8")
    return chr(len(toret)).encode("utf8") + toret

def make_parcel(msg):
    return chr(len(msg)).encode("utf8") + msg

def bindRequest(v, name, passwd):
    return chr(0x23).encode("utf8") + chr(v).encode("utf8") + \
        pstring(name) + pstring(passwd)

if __name__ == "__main__":
    import binascii
    assert binascii.hexlify(pstring("teststring")) \
        == b'0a74657374737472696e67'
    assert binascii.hexlify(bindRequest(1, "user", "pass")) \
        == b'230104757365720470617373'
    assert binascii.hexlify(make_parcel(bindRequest(1, "user", "pass"))) \
        == b'0c230104757365720470617373'
