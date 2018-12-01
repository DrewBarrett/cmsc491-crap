#!/usr/bin/env python3

import socket

SERVER = ("notanexploit.club", 9090)

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
        i += nlen + 1
    return ret

def make_parcel(msg):
    return chr(len(msg)).encode("utf8") + msg

def bindRequest(v, name, passwd):
    return chr(0x23).encode("utf8") + chr(v).encode("utf8") + \
        pstring(name) + pstring(passwd)

def searchRequest(count, filt=None):
    ret = chr(0x30).encode("utf8") + chr(count).encode("utf8")
    if filt:
        ret += chr(0x2b).encode("utf8") + filt
    else:
        ret += chr(0x23).encode("utf8")
    return ret

def filter(attr, val):
    return pstring(attr) + pstring(val)

def get_response(s):
    l = s.recv(1)
    l = int.from_bytes(l, byteorder='little')
    r = bytes()
    while l > 0:
        t = s.recv(l)
        l -= len(t)
        r += t
    return r

def parse_message(res):
    if res[0] == 0x24 or res[0] == 0x42:
        if res[1] != 0x77:
            print("Error: failed to connect")
            print(ppstring(res[2:])[0])
            exit(1)
    elif res[0] == 0x41:
        return ppstring(res[2:])
    else:
        print("Unknown response!")
        exit(2)


if __name__ == "__main__":
    import binascii
    assert binascii.hexlify(pstring("teststring")) \
        == b'0a74657374737472696e67'
    assert binascii.hexlify(bindRequest(1, "user", "pass")) \
        == b'230104757365720470617373'
    assert binascii.hexlify(make_parcel(bindRequest(1, "user", "pass"))) \
        == b'0c230104757365720470617373'
    assert binascii.hexlify(searchRequest(4, None)) \
        == b'300423'
    assert binascii.hexlify(searchRequest(4, \
                            filter("type","protocol"))) \
        == b'30042b04747970650870726f746f636f6c'

    s = socket.socket()
    s.connect(SERVER)
    s.sendall(make_parcel(bindRequest(1, "dbarret1", "letmein")))
    res = get_response(s)
    parse_message(res)
    s.sendall(make_parcel(searchRequest(4, None)))
    sres = []
    while True:
        res = get_response(s)
        if res[0] != 0x41:
            parse_message(res)
            break
        res = parse_message(res)
        sres.append(res)
    print("Results:")
    for i in sres:
        print('----')
        j = 0
        while j < len(i):
            print(i[j] + ':', i[j+1])
            j += 2
    exit(0)
