from csv import Sniffer
import os
import struct
from ctypes import *
import socket

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

host = get_ip_address()
is_windows = True if os.name == 'nt' else False

class IP(Structure): 
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte,4),
        ("tos", c_ubyte, 8),
        ("len", c_ushort, 16),
        ("id", c_ushort, 16),
        ("offset", c_ushort, 16),
        ("ttl", c_ubyte, 8),
        ("protocol_num", c_ubyte, 8),
        ("sum", c_ushort, 16),
        ("src", c_uint, 32),
        ("dst", c_uint, 32)
    ]
    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer = None):
        self.protocol_map = {1: "ICMP", 6 : "TCP", 17 : "UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<I", self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

socket_protocol = socket.IPPROTO_IP if is_windows else socket.IPPROTO_ICMP
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if is_windows:
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except:
        print('using windows[*]')
        exit(1)

try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0]
        ip_header = IP(raw_buffer)
        print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
except KeyboardInterrupt:
    try:
        if is_windows:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except:
        print('using windows[*]')
        exit(1)