import socket
import struct
import textwrap


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:+')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('IPV4 packet: ')
            print('Version: {}, Header Length: {}, TTL {}'.format(version, header_length, ttl))
            print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # icmp
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('ICMO Packet:')
                print('Type: {}, Code {}, Checksum {}'.format(icmp_type, code, checksum))
                print('Data: ')
                print(format(data))

            # tcp
            elif proto == 6:
                (src_port, dest_port, sequence, aknowledgement, flag_urg, flag_ask, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print('Tcp segment: ')
                print('Source port: {}, DEstanation port: {}'.format(src_port, dest_port))
                print('Sequence: {}, Acknoledgement: {}'.format(sequence, aknowledgement))
                print('Flags: ')
                print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ask, flag_psh, flag_rst, flag_syn, flag_fin))
                print('Data: ')
                print(format(data))

            # udp
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print('UDP segm: ')
                print('Source port: {}, Destanatiom port: {}, Length: {}'.format(src_port, dest_port, length))

            # other
            else:
                print('Data: ')
                print(format(data))

        else:
            print('Data: ')
            print(format(data))


# unpack ethernet ! net big-endian
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])   # 14byts
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# format mac addr        aa:bb:cc:dd:ee:ff
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# unpack ipv4
def ipv4_packet(data):
     version_header_length = data[0]
     version = version_header_length >> 4
     header_length = (version_header_length & 15) * 4
     ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
     return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# formatting ipv4 addr
def ipv4(addr):
    return'.'.join(map(str, addr))


# unpackicmp data
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# unpack tcp data
def tcp_segment(data):
    (src_port, dest_port, sequence, aknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags % 32) >> 5
    flag_ask = (offset_reserved_flags % 16) >> 4
    flag_psh = (offset_reserved_flags % 8) >> 3
    flag_rst = (offset_reserved_flags % 4) >> 2
    flag_syn = (offset_reserved_flags % 2) >> 1
    flag_fin = offset_reserved_flags % 1
    return src_port, dest_port, sequence, aknowledgement, flag_urg, flag_ask, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# unpack udp data
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# format multiline data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])






main()
