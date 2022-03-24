import socket
import os
from ctypes import *
import struct


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

is_windows = True if os.name == 'nt' else False
host = get_ip_address()

if is_windows:
    socket_protocol = socket.IPPROTO_IP
else: 
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host,0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)

if is_windows:
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except:
        print('are you in a unix enviroment?')
        exit(1)

print(sniffer.recvfrom(65565))

if is_windows:
    try:
        sniffer.IOCTL(socket.SIO_RCVALL,socket.RCVALL_OFF)
    except:
        print('para de usar windows caraio')
        exit(1)
