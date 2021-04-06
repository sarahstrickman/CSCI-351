"""
Project 1 for CSCI-351. This is a simple packet sniffer.

project reqs not implemented: filtering by netmask and boolean filtering
    I'm sorry :(

Due date:   Sept 16. 2020

filename:   pktsniffer.py
author:     Sarah Strickman     sxs4599@rit.edu
"""
import sys, socket, struct, binascii, os, scapy, typing

import scapy.all as scapie
from dataclasses import dataclass

from typing import List

USAGE_MESSAGE = "Usage: pktsniffer [-r filename] [-c filters]"

@dataclass
class UdpPacket:
    source_port: int
    destination_port: int
    length: int
    checksum: int

    def toList(self):
        return [("Source port", str(self.source_port)),
                ("Destination port", str(self.destination_port)),
                ("Length", str(self.length)),
                ("Checksum", hex(int(str(self.checksum), base=16)))
                ]
@dataclass
class TcpPacket:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgement_number: int
    data_offset: int
    flags: int
    urgent_pointer_bit: int
    acknowledgement: int
    push: int
    reset: int
    syn: int
    fin: int
    window: int
    checksum: int
    urgent_pointer: int
    options: int
    def toList(self):
        return [("Source port", self.source_port),
                ("Destination port", self.destination_port),
                ("Acknowledgement number", str(self.acknowledgement_number)),
                ("Data offset", str(self.data_offset) + " Bytes"),
                ("Flags", hex(int(str(self.flags), base=16))),
                ("\t.." + str(self.urgent_pointer_bit) + ". ....", ("No " if self.urgent_pointer_bit == 0 else "") + "Urgent pointer"),
                ("\t..." + str(self.acknowledgement) + " ....", ("No " if self.acknowledgement == 0 else "") + "Acknowledgement"),
                ("\t.... " + str(self.push) + "...", ("No " if self.push == 0 else "") + "Push"),
                ("\t.... ." + str(self.reset) + "..", ("No " if self.reset == 0 else "") + "Reset"),
                ("\t.... .." + str(self.syn) + ".", ("No " if self.syn == 0 else "") + "Syn"),
                ("\t.... ..." + str(self.fin) + "", ("No " if self.fin == 0 else "") + "Fin"),
                ("Window", str(self.window)),
                ("Checksum", hex(int(str(self.checksum), base=16))),
                ("Urgent Pointer", str(self.urgent_pointer)),
                ("Options", "None" if self.options.__len__() == 0 else self.options.hex())]
@dataclass
class IcmpPacket:
    icmp_type: int
    code: int
    checksum: int

    def toList(self):
        return [("Type", str(self.icmp_type)),
                ("Code", str(self.code)),
                ("Checksum", hex(int(str(self.checksum), base=16)))]
@dataclass
class Ipv4Packet:
    serviceType: str  # type of service
    precedence: int
    normalDelay: int
    normalThroughput: int
    normalReliability: int
    totalSize: int  # size of IP_Header + Payload
    identification: int  # for fragmentation. All fragments of same packet have same ident
    flags: str
    doNotFragment: int
    lastFragment: int
    fragmentOffset: int  # fragment offset in bytes
    timeToLive: int  # in seconds/hops
    protocol: int  # 17 is UDP, 6 is TCP, 1 is ICMP
    headerChecksum: int
    source: str  # [0] is ip address, [1] is hostname
    destination: str  # [0] is ip address, [1] is hostname
    payload: typing.Union[bytes, UdpPacket, TcpPacket, IcmpPacket]
    options: int
    headerLength: int = 20  # size of the header

    def toList(self):
        """
        :return: fields to print (in order)
        """
        return [("Header Length", str(self.headerLength) + " bytes"),
                ("Type of Service", self.serviceType),
                ("\txxx. ....", str(self.precedence) + " (precedence)"),
                ("\t..." + str(self.normalDelay) + " ....)", "normal delay"),
                ("\t.... " + str(self.normalThroughput) + "...)", "normal throughput"),
                ("\t.... ." + str(self.normalReliability) + "..)", "normal reliability"),
                ("Total Length", str(self.totalSize) + " bytes"),
                ("Identification", str(self.identification)),
                ("Flags", self.flags),
                ("\t." + str(self.doNotFragment) + "... ....", ("Do not fragment" if self.doNotFragment == 0 else "Fragment")),
                ("\t.." + str(self.doNotFragment) + ".. ....", "Last fragment"),
                ("Fragment offset", str(self.fragmentOffset) + " bytes"),
                ("Time to live", str(self.timeToLive) + " seconds/hops"),
                ("Protocol", str(self.protocol) + " (" + get_protocol_name(self.protocol) + ")"),
                ("Header checksum", hex(int(str(self.headerChecksum), base=16))),
                ("Source address", self.source),
                ("Destination address", self.destination),
                ("Options", "None" if self.options.__len__() == 0 else str(self.options))
                ]
@dataclass
class Ipv6Packet:
    headerLength: int

    def toList(self):
        return []
@dataclass
class IpPacket:
    version: int
    packetData: typing.Union[Ipv4Packet, Ipv6Packet]

    def toList(self):
        b = []
        b.append(("Version", self.version))
        for i in self.packetData.toList():
            b.append(i)
        return b
@dataclass
class EthernetPacket:
    destination: str  # destination address
    source: str  # source address
    protocol_type: int  # protocol type (IP is 0800)
    size: int  # size of the ethernet frame
    payload: typing.Union[None, bytes, IpPacket]  # contents of the frame (just the rest of the packet)

    def toList(self):
        """
        :return: stuff to print
        """
        return [("Packet size", str(self.size) + " bytes"),
                ("Destination", self.destination),
                ("Source", self.source),
                ("Ethertype", str(self.protocol_type))
                ]

def flatten(pkts):
    """
    flatten a linked list packet structure.
    :param pkts: list of ethernet frames
    :return: list of ethernet frames, IP packets, and UDP/TCP/ICMP packets
    """
    l = []
    for pk in pkts:
        l.append(pk)
        pd = pk.payload
        if isinstance(pd, IpPacket):
            l.append(pd)
            c = pd.packetData.payload
            if isinstance(c, UdpPacket) or isinstance(c, TcpPacket) or isinstance(c, IcmpPacket):
                l.append(c)
    return l
def get_pktType(a):
    if isinstance(a, EthernetPacket):
        return "ETHER"
    elif isinstance(a, IpPacket):
        return "IP"
    elif isinstance(a, UdpPacket):
        return "UDP"
    elif isinstance(a, IcmpPacket):
        return "ICMP"
    elif isinstance(a, TcpPacket):
        return "TCP"
    else:
        return "UNKNOWN"
def get_protocol_name(a):
    # 17 is UDP, 6 is TCP, 1 is ICMP
    if a == 17:
        return "UDP"
    elif a == 6:
        return "TCP"
    elif a == 1:
        return "ICMP"
    else:
        return "Unknown Type"
def get_title(a):
    if a == "ETHER":
        return "\t==== Ether Header ===="
    elif a == "IP":
        return "\t==== IP Header ===="
    elif a == "UDP":
        return "\t==== UDP Header ===="
    elif a == "TCP":
        return "\t==== TCP Header ===="
    elif a == "ICMP":
        return "\t==== ICMP Header ===="
    else:
        return "\t==== UNKNOWN Header ===="
def mac_address_string(a):
    """
    returns the string representation of a MAC address
    :param a: 6 byte MAC address
    :return: string representation
    """
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]), (a[1]), (a[2]), (a[3]), (a[4]), (a[5]))
    return b
def ip_address_string(a):
    """
    returns the string representation of an IP address
    :param a: a 4 byte IP address
    :return: string representation
    """
    b = "%x.%.x.%x.%x" % (socket.ntohs(a[0]), socket.ntohs(a[1]), socket.ntohs(a[2]), socket.ntohs(a[3]))
    return b
def print_packets(packets: List):
    """
    print the packets
    :param packets: list of EthernetPackets
    :return: none
    """
    for pkt in packets:
        pkt_type = get_pktType(pkt)
        print(pkt_type + ":" + get_title(pkt_type))
        for item in pkt.toList():
            print(pkt_type + ":\t" + item[0] + " = " + str(item[1]))
        print(pkt_type + ":")

def sniff_from_network(filters=None):
    """
    Sniff packets from the network using sockets.

    :param filters: Any filters to be applied to the sniff.
    """
    s = None
    if os.name == "nt":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(("127.0.0.1", 32007))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    while True:
        pkt = s.recvfrom(5678)
        # process the packet
        processed = process_ethernet_frame(pkt[0])
        if processed.protocol_type == 8:
            print(process_ethernet_frame(pkt[0]))
def get_filename(args):
    """
    Gets the filename to read packets from.  This is the argument inputted
    after the "-r" flag.  If the -r flag is the last parameter or if the
    following parameter is also a flag (begins with a "-" character),
    print an error message and exit.

    :param args:       array of command line arguments. This is system.argv

    :return:     If there is no "-r" flag specified, return None
                Otherwise, return the name of the file.
    """

    i = 1  # points to 1 index ahead of the loop
    for item in args:
        if item == "-r":
            if i >= (len(sys.argv)) or sys.argv[i][0] == "-":
                sys.exit(USAGE_MESSAGE + "\nMissing filename")
            return sys.argv[i]
        i += 1
    return None
def get_filters(args):
    """
    get the specified filters for limiting packets (specified by the "-c" flag
    :param args:       array of command line arguments. This is system.argv
    :return: list of filter keywords
    """
    i = 1  # points to 1 index ahead of the loop
    filters = []
    for item in args:
        if item == "-c":
            if i >= (len(sys.argv)) or sys.argv[i][0] == "-":
                sys.exit(USAGE_MESSAGE + "\nInvalid filters format")
            filters = sys.argv[i:]
            break
        i += 1
    return filters
def process_ethernet_frame(pkt):
    """
    Processes a single ethernet frame.
    :param pkt: Bytes object representing the received packet
    :return: EthernetPacket object
    """
    pkt_copy = pkt
    extraction_pattern = '!6s6sH'  # little endian, 6 string, 6 string, 1 Unsigned Short

    ethernet_size = pkt_copy.__len__()
    pkt_header = struct.unpack(extraction_pattern, bytes(pkt_copy[:14]))  # 14 is minimum buffer length

    source_addr = mac_address_string(pkt_copy[0:6])
    destination_addr = mac_address_string(pkt_copy[6:12])
    protocol_type = socket.ntohs(pkt_header[2])
    contents = pkt_copy[14:]  # from the header to the end

    if protocol_type == 8 and contents.__len__() > 20:
        # process the IP packet internally
        contents = process_ip_frame(contents)
    return EthernetPacket(destination=destination_addr, source=source_addr,
                          protocol_type=protocol_type, size=ethernet_size, payload=contents)
def process_ip_frame(pkt):
    """
    Processes a single ip packet.
    :param pkt: Bytes object representing the received packet
    :return:
    """
    ip_header = pkt[:20]
    version = struct.unpack('!B', ip_header[:1])[0] >> 4
    data = pkt[20:]
    if version == 4:  # ipv4 packet
        # parse ipv4 packet
        header = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ihl = header[0] & 0xF  # 0 is version and ihl
        header_length = 20
        type_of_service = hex(int(str(header[1] & 0xfc), base=16))  # first 6 bits
        precedence = header[1] & 0xe0
        delay = header[1] & 0x10
        throughput = header[1] & 0x08
        reliability = header[1] * 0x04
        ecn = header[1] & 0x03  # last 2 bits

        totalLength = header[2]
        ident = header[3]
        flags = hex(int(str(header[4] >> 12), base=16))     # first 3 bits
        donot_fragment = 0 if ((header[4] & 0x4000) == 0) else 1
        fragment = 0 if ((header[4] & 0x2000) == 0) else 1
        offset = header[4] & 0x1fff
        ttl = header[5]
        protocol = header[6]
        options = pkt[20:ihl * 4]
        contents = pkt[ihl * 4:]    # ihl * 4 is header length plus options
        if protocol == 17:
            contents = process_udp_frame(pkt[ihl * 4:])
        if protocol == 6:
            contents = process_tcp_frame(pkt[ihl * 4:])
        if protocol == 1:
            contents = process_icmp_frame(pkt[ihl * 4:])
        chksum = header[7]
        src = socket.inet_ntoa(header[8])
        dest = socket.inet_ntoa(header[9])
        data = Ipv4Packet(serviceType=type_of_service,
                          precedence=precedence,
                          normalDelay=delay,
                          normalThroughput=throughput,
                          normalReliability=reliability,
                          totalSize=totalLength,
                          identification=ident,
                          flags=flags,
                          doNotFragment=donot_fragment,
                          lastFragment=fragment,
                          fragmentOffset=offset,
                          timeToLive=ttl,
                          protocol=protocol,
                          headerChecksum=chksum,
                          source=src,
                          destination=dest,
                          payload=contents,
                          options=options)
        return IpPacket(version=version, packetData=data)
    else:
        return pkt  # ipv6 not implemented
def process_udp_frame(pkt):
    """
    process a single udp packet
    :param pkt:
    :return: a UdpPacket object
    """
    header = struct.unpack('!HHHH', pkt[:8])    # last 4 bytes are CRC
    src = header[0]
    dest = header[1]
    length = header[2]
    chksm = header[3]
    return UdpPacket(source_port=src,
                     destination_port=dest,
                     length=length,
                     checksum=chksm)
def process_icmp_frame(pkt):
    """
    process a single icmp packet
    :param pkt:
    :return: a IcmpPacket object
    """
    header = struct.unpack('!BBH', pkt[:4])    # last 4 bytes are CRC
    tp = header[0]
    cd = header[1]
    chksm = header[2]
    return IcmpPacket(icmp_type=tp,
                      code=cd,
                      checksum=chksm)
def process_tcp_frame(pkt):
    """
    process a single tcp packet
    :param pkt: some bytes
    :return: a TcpPacket object
    """
    header = struct.unpack('!HHLLBBHHH', pkt[:20])    # last 4 bytes are CRC
    src = header[0]
    dest = header[1]
    sequence_num = header[2]
    ack = header[3]
    offset = header[4] >> 4
    reserved = header[4] & 0x38
    ns = header[4] & 0x01
    flags = header[5]
    cwr = header[5] & 0x80
    ece = header[5] & 0x40
    urg = header[5] & 0x20
    ack_bit = header[5] & 0x10
    psh = header[5] & 0x08
    rst = header[5] & 0x04
    syn = header[5] & 0x02
    fin = header[5] & 0x01
    wndw_sze = header[6]
    chksm = header[7]
    urg_ptr = header[8]
    options_bytes = pkt[20:]
    return TcpPacket(source_port=src,
                     destination_port=dest,
                     sequence_number=sequence_num,
                     acknowledgement_number=ack,
                     data_offset=offset,
                     flags=flags,
                     urgent_pointer_bit=urg,
                     acknowledgement=ack_bit,
                     push=psh,
                     reset=rst,
                     syn=syn,
                     fin=fin,
                     window=wndw_sze,
                     checksum=chksm,
                     urgent_pointer=urg_ptr,
                     options=options_bytes)

def read_file(filename):
    """
    reads the specified pcap file and processes the packets.  If not a pcap file, this returns none.

    :param filename: name of the file to be read
    :return: list of packets that were found
    """
    packet_list = []
    if filename is None or filename.split('.')[-1] != "pcap":
        print("Invalid filename. Not a pcap file")
        return None
    scapy_cap = scapie.rdpcap(filename)
    for packet in scapy_cap:
        pk = process_ethernet_frame(bytes(packet))
        packet_list.append(pk)
    return packet_list  # will be a linked list of sorts

def isInNet(addr, netmask):
    netmask = netmask.split(".")
    pksplit = addr.split(".")
    for i in range(0, 4):
        if netmask[i] == 0 or netmask[i] == 'x' or netmask[i] == pksplit[i]:
            # it's in
            continue
        else:
            return False
    return True
def filterList(packets, filter):
    """
    filter packets by a single specification
    :param packets: packet list
    :param filter: filter specification
    :return: list of packets (filtered)
    """
    filtered_lst = []
    if filter[0] == "tcp":
        for pk in packets:
            if isinstance(pk, TcpPacket):
                filtered_lst.append(pk)
    elif filter[0] == "udp":
        for pk in packets:
            if isinstance(pk, UdpPacket):
                filtered_lst.append(pk)
    elif filter[0] == "icmp":
        for pk in packets:
            if isinstance(pk, IcmpPacket):
                filtered_lst.append(pk)
    elif filter[0] == "ip":
        for pk in packets:
            if isinstance(pk, TcpPacket):
                filtered_lst.append(pk)
    elif filter[0] == "host":
        for pk in packets:
            if isinstance(pk, IpPacket):
                pl = pk.packetData
                if pl.source == filter[1] or pl.destination == filter[1]:
                    filtered_lst.append(pk)
    elif filter[0] == "port":
        for pk in packets:
            if isinstance(pk, UdpPacket) or isinstance(pk, TcpPacket):
                if pk.source_port == int(filter[1]) or pk.destination_port == int(filter[1]):
                    filtered_lst.append(pk)
    elif filter[0] == "net":
        netmask = filter[1]
        for pk in packets:
            if isinstance(pk, IpPacket):
                pl = pk.packetData
                if isInNet(pl.source, netmask) or isInNet(pl.destination, netmask):
                    filtered_lst.append(pk)
    return filtered_lst
def filter(packetList, filters):
    i = 0   # index of filters
    final_pktlist = packetList
    filterA = []
    filterB = []
    boolean = ""
    maxSize = -1
    while i < len(filters):
        if filters[i].isnumeric():
            maxSize = int(filters[i])
            i += 1
        elif filters[i].lower() == "tcp" or filters[i].lower() == "icmp" or filters[i].lower() == "udp" or filters[i].lower() == "ip":
            # filterA = filterList(packetList, [filters[i]])
            final_pktlist = filterList(packetList, [filters[i]])
            i += 1
            # if boolean == "and":
            #     for pk in final_pktlist:
            #         if pk not in filterA:
            #             final_pktlist.remove(pk)
            #     filterA = []
            # elif boolean == "or":
            #     if pk in packetList:
            #         if pk not in final_pktlist and pk in filterA:
            #             final_pktlist.append(pk)
        elif filters[i].lower() == "host" or filters[i].lower() == "port" or filters[i].lower() == "net":
            # filterA = filterList(packetList, [filter[i], filter[i + 0]])
            final_pktlist = filterList(packetList, [filters[i], filters[i + 1]])
            i += 2
    # apply maxSize
    if maxSize < 0 or maxSize > len(final_pktlist):
        return final_pktlist
    else:
        return final_pktlist[:maxSize]


def main():
    """
    Main function. Checks arguments and runs other functions accordingly.
    Format of args: pktsniffer [-r filename] [-c filters]
    """
    filename = get_filename(sys.argv)
    packets = []
    packets_flat = []
    if filename is None:
        # analyze packets from network
        sniff_from_network()
    else:
        # get packets from filename
        packets = read_file(filename)
        packets_flat = flatten(packets)
    filters = get_filters(sys.argv)
    try:
        packets_flat = filter(packets_flat, filters)    # do filtering
    except:
        raise Exception("Invalid filter command: " + str(filters))

    print_packets(packets_flat)

if __name__ == "__main__":
    main()
