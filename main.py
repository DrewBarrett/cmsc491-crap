#!/usr/bin/env python3

import socket

def pstring(instr):
    toret = instr.encode("utf8")
    return chr(len(toret)).encode("utf8") + toret

def ppstring(pstrings):
    ret = []
    l = len(pstrings)
    i = 0
    while i < l - 1:
        nlen = pstrings[i]
        msg = pstrings[i+1:i+nlen+1].decode()
        ret.append(msg)
        i += nlen
    return ret

def make_parcel(msg):
    return chr(len(msg)).encode("utf8") + msg

def bindRequest(v, name, passwd):
    return chr(0x23).encode("utf8") + chr(v).encode("utf8") + \
        pstring(name) + pstring(passwd)

def get_response(s):
    l = s.recv(1)
    l = int.from_bytes(l, byteorder='little')
    r = bytes()
    while l > 0:
        t = s.recv(l)
        l -= len(t)
        r += t
    return r

if __name__ == "__main__":
    import binascii
    assert binascii.hexlify(pstring("teststring")) \
        == b'0a74657374737472696e67'
    assert binascii.hexlify(bindRequest(1, "user", "pass")) \
        == b'230104757365720470617373'
    assert binascii.hexlify(make_parcel(bindRequest(1, "user", "pass"))) \
        == b'0c230104757365720470617373'

    s = socket.socket()
    s.connect(("notanexploit.club", 9090))
    while True:
        s.sendall(make_parcel(bindRequest(1, "dbarret1", "letmei")))
        res = get_response(s)
        if len(res) == 0:
            continue
        print(ppstring(res[2:]))
        if res[0] == 0x24 and res[1] == 0x77:
            break

