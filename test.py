import socket


UDP = 0x0011
stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, UDP)


while True:
    data, address = stealer.recvfrom(4096)
    print()