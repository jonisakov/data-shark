# Imports
from scapy.all import *
# import re
import statistics

from scapy.layers.dhcp import DHCP
from scapy.layers.inet import TCP, IP, Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
class PcapReader(object):
    """will read a pcap file and preform certain functions on the data"""

    # def __init__(self, *args, **kwargs):
    def __init__(self):
        # FIN = 0x01
        # SYN = 0x02
        # RST = 0x04
        # PSH = 0x08
        # ACK = 0x10
        # URG = 0x20
        # ECE = 0x40
        # CWR = 0x80
        self.location = ''
        self.sessions = []
        self.packets = []
        self.srcIps = []
        self.convs = []
        self.srcMacs = []
        self.whohas = []
        self.isat = []

    def read(self, location):
        """
        will read and store a pcap file info
        """
        self.packets = rdpcap(location)
        self.location = location
        self.sessions = rdpcap(location).sessions()

    def listhosts(self, layer=3):
        """
        returns a list of hosts listed in the pcap, can be either MAC or IP
        listhosts(type) --> returns list of type
        
        layer - default IP can be either 3,2
        """

        # runs through all packets and searches for IP packets

        # checks for wrong arguments
        if layer not in [2, 3]:
            raise ValueError("layer should contain supported layer")
        if layer == 3:
            self.srcIps = []
            for PACKET in self.packets:
                if PACKET.haslayer(IP):
                    self.srcIps.append(PACKET.getlayer(IP).src)
                    self.srcIps.append(PACKET.getlayer(IP).dst)
            return list(dict.fromkeys(self.srcIps))
        # runs through all packets and searches for IP packets
        if layer == 2:
            self.srcMacs = []
            for PACKET in self.packets:
                if PACKET.haslayer(ARP):
                    self.srcMacs.append(PACKET.getlayer(Ether).src)
                    self.srcMacs.append(PACKET.getlayer(Ether).dst)
            return list(dict.fromkeys(self.srcMacs))

    def listconvs(self):
        """returns a list of conversations by src,dst data
        listconvs(type) --> returns list of type
        
        layer - default IP can be either 3,2"""

        # runs through all packets and searches for IP packets

        # checks for wrong arguments
        ACK = 0x10
        SYN = 0x02
        self.convs = []
        for PACKET in self.packets:
            if PACKET.haslayer(TCP):
                if PACKET[TCP].flags & SYN and PACKET[TCP].flags & ACK and not PACKET.haslayer(IPv6):
                    self.convs.append([PACKET.getlayer(IP).dst, PACKET.getlayer(IP).src, PACKET.getlayer(TCP).sport])
        return self.convs

    def listarps(self):
        """
        listarps(self) -> creates all the whohas/ isat arrays of arp
        will be used in order to detect different arp attacks by the type of arp
        sent 
        """
        self.whohas = []
        self.isat = []
        for PACKET in self.packets:
            if PACKET.haslayer(ARP):
                # checks who asked the arp request the opcode for this is 1
                if PACKET[ARP].op == 1:
                    self.whohas.append([PACKET.src, PACKET.dst, PACKET.psrc, PACKET.pdst])
                # checks who answered and what is the answer the opcode for this is 2
                if PACKET[ARP].op == 2:
                    self.isat.append([PACKET.src, PACKET.dst, PACKET.psrc, PACKET.pdst])

    def doubletag(self):
        """
        doubletag(self) -> will return an array of all vlan double tagged
        for the vlan double tagging attack
        """
        # checks for two tags of dot1Q

        attacker_dict = {}
        for PACKET in self.packets:
            counter = 0
            dot1q = 0
            layers = []
            while True:
                layer = PACKET.getlayer(counter)
                if layer is None:
                    break
                if layer.name == "802.1Q":
                    dot1q = dot1q + 1
                    layers.append(str(PACKET.getlayer(counter).vlan))
                if dot1q == 2:
                    print("double vlan tagging from " + PACKET[Ether].src + "using tags " + layers[0] + ", " + layers[1])
                    attacker_dict[PACKET[Ether].src] = f'Tags: {layers[0]} and {layers[1]}'
                    break

                counter += 1
        return attacker_dict    
        
    def dhcp_detection(self):
        """
        dhcp_detection(self) -> (req, offers, acks)
        returns who asked[], the ip it received[], who answered[]
        will go through all packets and retrieve the relevant data regarding dhcp requests
        and data needed to detect attacks
        """
        requesting = []
        offers = []
        acks = []
        for PACKET in self.packets:
            if PACKET.haslayer(DHCP):
                options = PACKET[DHCP].options

                # DHCPDISCOVER
                if options[0][1] == 1:
                    requesting.append(PACKET[Ether].src)

                # DHCPOFFER 
                if options[0][1] == 2:
                    offers.append([PACKET.getlayer(3).yiaddr, PACKET.getlayer(3).siaddr, PACKET[Ether].dst])

                # DHCPACK
                if options[0][1] == 5:
                    acks.append([PACKET[IP].src, PACKET[IP].dst])

        return requesting, offers, acks

    def tcp_scan(self):
        """
        ONLY WORKS ON A SPECIFIC HOST
        rst_scan() -> all possible scans []
        will search for possible tcp scans in the file. if found will return the list of
        possible addresses in which there was a possible tcp scan
        ONLY WORKS ON A SPECIFIC HOST not a port sweep
        """

        convs = (self.packets.sessions().keys())
        streams = []
        ports = {}

        # run on all the conversations to count all TCP conversations 
        for conv in convs:
            if 'TCP' in conv:
                streams.append(conv.replace(":", " ").split(" "))

        # count sessions in stream
        for stream in streams:
            try:
                if stream[5] not in ports[stream[1], stream[4]]:
                    ports[stream[1], stream[4]].append(stream[5])
            except Exception as e:
                ports[stream[1], stream[4]] = [stream[5]]
                # logging.exception(e)

        # check for above 2 standard deviations of connections -> and return them
        connections = []
        # two_std = 0
        streams = []

        for port in ports:
            connections.append(len(ports[port]))

        if connections:
            std = statistics.stdev(connections)
            avg = sum(connections) / len(connections)
            avg_plus_std = avg + (std * 2)

            for port in ports:
                if len(ports[port]) > avg_plus_std:
                    streams.append(port)
            return streams

        else:
            return []