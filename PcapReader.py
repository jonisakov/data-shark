# Imports
from scapy.all import *
import re
import statistics

class PcapReader():
    """will read a pcap file and preform certain functions on the data"""
    def __init__(self, *args, **kwargs):
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80
        self.location = ''
        self.sessions = []
        

    def read(self, location):
        """will read and store a pcap file info"""
        self.packets = rdpcap(location)
        self.location = location
        self.sessions = rdpcap(location).sessions()

    def listhosts(self, layer = 3):
        """returns a list of hosts listed in the pcap, can be either MAC or IP
        listhosts(type) --> returns list of type
        
        layer - deafulte IP can be either 3,2"""

        # runs through all packets and serches for IP packets

        #checks for wrong arguments
        if(layer not in [2,3]):
            raise ValueError("layer should contain supported layer")
        if(layer == 3):
            self.srcIps = []
            for packet in self.packets:
                if(packet.haslayer(IP)):
                    self.srcIps.append(packet.getlayer(IP).src)
                    self.srcIps.append(packet.getlayer(IP).dst)
            return(list(dict.fromkeys(self.srcIps)))
        # runs through all packets and serches for IP packets
        if(layer == 2):
            self.srcMacs = []
            for packet in self.packets:
                if(packet.haslayer(ARP)):
                    self.srcMacs.append(packet.getlayer(Ether).src)
                    self.srcMacs.append(packet.getlayer(Ether).dst)
            return(list(dict.fromkeys(self.srcMacs)))
    def listconvs(self):
        """returns a list of conversations by src,dst data
        listconvs(type) --> returns list of type
        
        layer - deafulte IP can be either 3,2"""

        # runs through all packets and serches for IP packets

        #checks for wrong arguments
        ACK = 0x10
        SYN = 0x02
        self.convs = []
        for packet in self.packets:
            if(packet.haslayer(TCP)):
                if(packet[TCP].flags & SYN and packet[TCP].flags & ACK and not packet.haslayer(IPv6)):
                    self.convs.append([packet.getlayer(IP).dst,packet.getlayer(IP).src,packet.getlayer(TCP).sport])
        return(self.convs)     
            
                    
            
    def listarps(self):
        """
        listarps(self) -> creates all the whohas/ isat arrays of arp
        will be used in order to detect diffrent arp attacks by the type of arp
        sent 
        """
        self.whohas = []
        self.isat = []
        for packet in self.packets:
            if(packet.haslayer(ARP)):
                # checks who asked the arp request the opcode for this is 1
                if(packet[ARP].op ==1):
                    self.whohas.append([packet.src,packet.dst, packet.psrc, packet.pdst])
                # checks who answerd and what is the answer the opcode for this is 2
                if(packet[ARP].op ==2):
                    self.isat.append([packet.src,packet.dst, packet.psrc, packet.pdst])


    def doubletag(self):
        """
        doubletag(self) -> will return an array of all vlan double taged
        for the vlan double tagging attack
        """
        # checks for two tags of dot1Q
        for packet in self.packets:
                counter = 0
                dot1q = 0
                layers = []
                while True:
                    layer = packet.getlayer(counter)
                    if layer is None:
                        break
                    if (layer.name == "802.1Q"):
                        dot1q = dot1q + 1
                        layers.append(str(packet.getlayer(counter).vlan))
                    if (dot1q == 2):
                        print("double vlan tagging from " + packet[Ether].src + "using tags " + layers[0] + ", " + layers[1])
                        break

                    counter += 1

    def dhcp_detection(self):
        """
        dhcp_detection(self) -> (req, offers, acks)
        returns who asked[], the ip it recived[], who answered[]
        will go through all packets and retrive the relevent data regarding dhcp requests
        and data needed to detect attacks
        """
        requesting = []
        offers = []
        acks = []
        for packet in self.packets:
            if(packet.haslayer(DHCP)):
                options = packet[DHCP].options  

                # DHCPDISCOVER
                if(options[0][1] == 1):

                    requesting.append(packet[Ether].src)

                # DHCPOFFER 
                if(options[0][1] == 2):
                    offers.append([packet.getlayer(3).yiaddr,packet.getlayer(3).siaddr, packet[Ether].dst])


                # DHCPACK
                if(options[0][1] == 5):
                    acks.append([packet[IP].src, packet[IP].dst])

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
            if('TCP' in conv):
                streams.append(conv.replace(":", " ").split(" "))

        # count seasions in stream 
        for stream in streams:
            try:
                if(stream[5] not in ports[stream[1],stream[4]]):
                    ports[stream[1],stream[4]].append(stream[5])
            except :
                ports[stream[1],stream[4]] = [stream[5]]

        # check for above 2 standard deviations of connections -> and return them
        connections = []
        two_std = 0
        streams = []

        for port in ports:

            connections.append(len(ports[port]))

        std = statistics.stdev(connections)
        avg = sum(connections) / len(connections)
        avg_plus_std = avg + (std * 2)

        for port in ports:
            if(len(ports[port]) > avg_plus_std):
                streams.append(port)
        return(streams)














        
