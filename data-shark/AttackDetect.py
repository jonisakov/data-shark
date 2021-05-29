from scapy.contrib.cdp import CDPMsgDeviceID
from scapy.layers.inet import TCP, IP
import time# import PcapReader  
from scapy.all import *

load_contrib("cdp")


# import networkx as nx
# import matplotlib.pyplot as plt
# from matplotlib.lines import Line2D

class AttackDetect(object):
    """
    description of class
    """

    @staticmethod
    def arppoisoning(arps):
        """
        will detect arp poisoning with duplicate usage of the same ip from different sources
        """
        # K: ip , V: mac
        arp_table = {}
        arp_attacker = {}
        for arp in arps:
            # src_mac = arp[0]
            dst_mac = arp[1]
            # src_ip = arp[2]
            dst_ip = arp[3]
            try:
                # Let's check
                if arp_table[dst_ip] != dst_mac:
                    print(dst_ip + " is spoofed! please check the address")
                    print("spoofed by: " + arp_table[dst_ip] + " and " + dst_mac)
                    arp_attacker[dst_ip] = f'{arp_table[dst_ip]} and {dst_mac}'

                else:
                    arp_table[dst_ip] = dst_mac
            except Exception as e:
                arp_table[dst_ip] = dst_mac
                # logging.exception(e)
        return arp_attacker
    @staticmethod
    def cdp_mapping(packets):
        """
        cdp_spoof() -> will return all the cdp queries and types of query
        and if found any spoofing (above 10 request per device) will alert
        """
        # displays the cdp queries
        load_contrib("cdp")
        cdp_maps_detected = dict()
        cdp_packets = []

        for PACKET in packets:
            if CDPMsgDeviceID in PACKET:
                cdp_packets.append([PACKET.src, PACKET["CDPMsgDeviceID"].val.decode(), PACKET["CDPAddrRecordIPv4"].addr,PACKET.time])
                


        hosts = dict()
        for cdp_packet in cdp_packets:
            
            src_mac = cdp_packet[0]
            hosts[src_mac] = hosts.get(src_mac,{})
            last_host_cdp_count = hosts[src_mac].get('cdp_count',0)
            last_cdp_timestamp = hosts[src_mac].get('timestamp',cdp_packet[-1])
            last_cdp_interval = hosts[src_mac].get('last_interval',cdp_packet[-1])
            current_cdp_interval = cdp_packet[-1] - last_cdp_timestamp
            hosts[src_mac] = {'cdp_count' : last_host_cdp_count + 1 , 'last_interval' : current_cdp_interval , 'total_interval': current_cdp_interval + last_cdp_interval,  'timestamp': last_cdp_timestamp }

        for host in hosts.keys():
            host_cdp_count = hosts[host]['cdp_count']
            host_total_interval = hosts[host]['total_interval']
            host_cdp_rate = host_total_interval/host_cdp_count
            hosts[host] = {'cdp_count' : host_cdp_count,'cdp_rate': host_cdp_rate}
            if host_cdp_rate > 5: # 5 seconds for cdp is default
                print(f'The host: {host} has a unsual cdp rate of {host_cdp_rate}/s. 5 is default')
                cdp_maps_detected[host] = host_cdp_rate


        print(str(hosts))

        # spoofing to non duplicate      
        cdp_convs = []
        for packet in cdp_packets:
            if packet[0:3] not in cdp_convs:
                cdp_convs.append(packet[0:3])

        return cdp_convs, cdp_maps_detected

    @staticmethod
    def tcp_scan(streams, packets):
        """
        tcp_connect_scan(self, streams[], packets) -> return( str(dst_scan,src_scan), bool if_scanned)
        will use the data read from the pcap to determine if there was a possible tcp connect scan
        if there was one will inform to the source of the scan and the destination
        """
        # all_packets = 0
        # rst_packets = 0
        # will count the rst flagged packets percentage out of all the packets between the sources
        for stream in streams:
            all_packets = 0
            rst_packets = 0
            for PACKET in packets:
                if PACKET.haslayer(TCP):
                    if PACKET.getlayer(IP).src == stream[0] and PACKET.getlayer(IP).dst == stream[1]:
                        all_packets += 1
                        if PACKET[TCP].flags & 0x04:
                            rst_packets += 1
            # if one out of 6 packets is rst assume its a scan attack
            if all_packets / 6 < rst_packets:
                print("tcp_connect_scan was made by:" + str(stream[1]) + " on:" + str(stream[0]))
                return stream, True
        # no stream was found so return a false
        return ('0.0.0.0', '0.0.0.0'), False

    @staticmethod
    def generic_tcp_port_scan(streams, packets):
        """
        generic_tcp_port_scan(self, streams[], packets) -> return( {str(dst_scan) : str(src_scan) } , bool if_scanned)
        will use the data read from the pcap to determine if there was a possible generic port scan
        if there was one will inform to the source of the scan and the destination
        """

        # Dict: {Source_IP : Dest_IP}
        generic_tcp_port_scan = {}

        # will count the different destination ports within each session
        for stream in streams:
            different_ports = set()
            for PACKET in packets:
                if PACKET.haslayer(TCP):
                    if PACKET.getlayer(IP).src == stream[0] and PACKET.getlayer(IP).dst == stream[1]:
                        different_ports.add(PACKET.getlayer(TCP).dport)

            # Dport has more then X unique values, between 2 hosts
            if len(different_ports) > 500:
                print("generic_tcp_port_scan was made by:" + str(stream[0]) + " on:" + str(stream[1]) +
                      " with {} unique ports".format(len(different_ports)))
                generic_tcp_port_scan[str(stream[0])] = str(stream[1])

        # no stream was found so return a false
        if len(generic_tcp_port_scan) == 0:
            return {'0.0.0.0': '0.0.0.0'}, False

        # if one out of 6 packets is rst assume its a scan attack
        return generic_tcp_port_scan, True

    # def scan_type(self, scanned, packets):
    #     """
    #     scan_type -> return( str scan_type)
    #     will take the input from the scan and return the type of scan used in there
    #     after that it will know which ports are open in accord with the needed request and answer
    #     matching the scan type
    #     """
    #     FIN = 0x01
    #     SYN = 0x02
    #     RST = 0x04
    #     PSH = 0x08
    #     ACK = 0x10
    #     URG = 0x20
    #     ECE = 0x40
    #     CWR = 0x80
    #     for packet in packets:
    #         if packet.haslayer(TCP):
    #             if packet[TCP].src == scanned[1] and packet[TCP].dst == scanned[0]:
    #                 stream += packet
    #
    #     # check for connect scan
    #     for packet in stream:
    #         if packet[TCP].src == scanned[1] and not packet[TCP].flags & SYN:
    #             # either the tcp_connect or the tcp_stealth
    #             continue
