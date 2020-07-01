import PcapReader
from scapy.all import *
load_contrib("cdp")
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

class AttackDetect(object):
    """description of class"""


    def arpposioning(self, arps):
        """
        will detect arp posining with duplicate usage of the same ip from defrent sources,
        will also use the 
        """
        spoofed = {}
        for arp in arps:
            try:
                if (spoofed[arp[2]] != arp[0]):
                    print(arp[2] + " is spoofed! please check the address")
                    print("spoofed by: " + spoofed[arp[2]] + " and " + arp[1])
            except:
                spoofed[arp[3]] = arp[1]

    def cdp_mapping(self, packets):
        """
        cdp_spoof() -> will return all the cdp queirs and types of query 
        and if found any spoofing (above 10 request per device) will alert
        """
        # displays the cdp queries
        load_contrib("cdp")
        spoofing = []
        counter = []
        
        for packet in packets:
            if(CDPMsgDeviceID in packet):
                print("sent by: " + packet["CDPMsgDeviceID"].val.decode() + ", ip address: " + packet["CDPAddrRecordIPv4"].addr)
                spoofing.append([packet.src, packet["CDPMsgDeviceID"].val.decode(), packet["CDPAddrRecordIPv4"].addr])
                counter.append(packet.src)
        
        # prints the spoofing
        counts = dict()
        for mac in counter[0]:
            counts[mac] = counts.get(mac, 0) + 1

        # prints of there was a spoofing attempt
        for address in counts:
            if(counts[address] >= 10):
                print(address)
        
        # spoofing to non duplicate      
        new_spoofing = []
        for s in spoofing:
            if s not in new_spoofing:
                new_spoofing.append(s)


        return(new_spoofing)

    def tcp_scan(self, streams, packets):
        """
        tcp_connect_scan(self, strams[]) -> return( str(dst_scan,src_scan), boll if_scaned)
        will use the data read from the pcap to determen if there was a possible tcp connect scan
        if there was one will inform to the source of the scan and the destination
        """
        all_packets = 0
        rst_packets = 0
        # will count the rst flaged packets precentege out of all the packets between the sources
        for stream in streams:
            all_packets = 0
            rst_packets = 0
            for packet in packets:
                if(packet.haslayer(TCP)):
                    if(packet.getlayer(IP).src == stream[0] and packet.getlayer(IP).dst == stream[1]):
                        all_packets += 1
                        if(packet[TCP].flags & 0x04):
                            rst_packets += 1
            # if one out of 6 packets is rst assume its a scan attack
            if(all_packets / 6 < rst_packets):
                print("tcp_connect_scan was made by:" + str(stream[1]) + " on:" + str(stream[0]))
                return stream, True
        # no stream was found so return a flase
        return ('0.0.0.0', '0.0.0.0'), False


    def scan_type(self, scanned, packets):
        """
        scna_type -> return( str scan_type)
        will take the input from the scan and return the type of scan used in there
        after that it will know which ports are open in acord with the needed request and answer
        matching the scan type
        """
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80
        for packet in packets:
            if(packet.haslayer(TCP)):
                if(packet[TCP].src == scanned[1] and packet[TCP].dst == scanned[0]):
                    stream += packet

        # check for connect scan
        for packet in stream:
            if(packet[TCP].src == scanned[1] and not packet[TCP].flags & SYN):
                # either the tcp_connect or the tcp_stealth
                continue
