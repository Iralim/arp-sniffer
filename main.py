import socket
import time
import binascii
from threading import Thread


interface = 'enp0s3'
my_ip = '192.168.1.101'
my_mac = '08:00:27:be:43:b6'

ip_mac = {}

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((interface, 0))


def arp_parser(raw_ether):
    if raw_ether[12:14].hex() == '0806':
        dst_mac = raw_ether[:6]
        src_mac = raw_ether[6:12]
        eth_type = raw_ether[12:14].hex()
        ether_data = raw_ether[14:]
        hardware_type = raw_ether[14:16]
        protocol_type = raw_ether[16:18]
        hardware_size = raw_ether[18:19]
        protocol_size = raw_ether[19:20]
        opcode = raw_ether[20:22]
        sender_mac_addr = raw_ether[22:28]
        sender_ip_addr = raw_ether[28:32]
        target_mac_addr = raw_ether[32:38]
        target_ip_addr = raw_ether[38:42]
        rest = raw_ether[42:]
        arp_message = ''
        opcode_v = ''

        if int(opcode.hex()) == 1:
            opcode_v = "REQUEST"
        elif int(opcode.hex()) == 2:
            opcode_v = "REPLY"
        src_ipv4 = '.'.join(map(str, sender_ip_addr))
        dst_ipv4 = '.'.join(map(str, target_ip_addr))
        if dst_mac != b'\xff\xff\xff\xff\xff\xff' and sender_ip_addr != b'\x00\x00\x00\x00' and opcode_v == 'REPLY':
            arp_message = f'{opcode_v} - {src_ipv4} at {sender_mac_addr.hex(":")}'
        if sender_mac_addr != b'\x00\x00\x00\x00\x00\x00' and \
                sender_ip_addr != b'\x00\x00\x00\x00' and \
                target_mac_addr == b'\x00\x00\x00\x00\x00\x00' and \
                target_ip_addr != b'\x00\x00\x00\x00' and \
                sender_ip_addr != target_ip_addr and opcode_v == 'REQUEST':
            arp_message = f'{opcode_v} - Who is at {target_ip_addr} Tell to {sender_mac_addr}'

        return sender_mac_addr, sender_ip_addr, target_mac_addr, target_ip_addr, arp_message, opcode_v

def arp_sniffer():

    r = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data = r.recvfrom(60)[0]
        if raw_data[12:14].hex() == '0806':
            sender_mac_addr, sender_ip_addr, target_mac_addr, target_ip_addr, arp_message, opcode_v = arp_parser(raw_data)

            if opcode_v == "REPLY" and f'{".".join(map(str, sender_ip_addr))}' not in ip_mac.keys():
                ip_mac[f'{".".join(map(str, sender_ip_addr))}'] = f'{sender_mac_addr.hex(":")}'
                print(arp_message)

            elif f'{".".join(map(str, sender_ip_addr))}' in ip_mac.keys() \
                    and ip_mac[f'{".".join(map(str, sender_ip_addr))}'] != sender_mac_addr.hex(':'):
                print(f"---!!!--- arp spoofing detected ---!!!--->>> ({arp_message})".upper())

def send_arp_request_255():

    ethernet_broadcast = b'\xff\xff\xff\xff\xff\xff'
    ethernet_source = binascii.unhexlify(my_mac.replace(':', ''))
    e_h_p_h_p_o = b'\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01'
    sender_mac_addr = binascii.unhexlify(my_mac.replace(':', ''))
    sender_ip_addr = bytes(map(int, my_ip.split('.')))
    target_mac_addr = b'\x00\x00\x00\x00\x00\x00'
    time.sleep(1)
    for i in range(1, 256):
        send_target_ip = my_ip[:10] + str(i)
        ip_bytes = bytes(map(int, send_target_ip.split('.')))
        target_ip_addr = ip_bytes
        arp_frame = ethernet_broadcast + \
                    ethernet_source + \
                    e_h_p_h_p_o + \
                    sender_mac_addr + \
                    sender_ip_addr + \
                    target_mac_addr + \
                    target_ip_addr

        s.send(arp_frame)
        time.sleep(0.01)

    print("========================================================")



def main():

    Thread(target=arp_sniffer).start()
    send_arp_request_255()
    print("Host list:")
    for key, value in ip_mac.items():
        print(key + " " + value)
    print("========================================================")


if __name__ == "__main__":
    main()















