# IMPORTS
# from scapy.all import *
import re
from PcapReader import PcapReader
# import networkx as nx
from NetScheme import NetScheme
from AttackDetect import AttackDetect
import argparse
from Machine_Learning import Machine_Learning
from report_engine import ReportEngine


def main():
    # Create the parser
    parser = argparse.ArgumentParser(prog='data_shark.py',
                                     description='''Data-Shark a network forensics tool aimed
                                     at helping you detect and view all the needed data for
                                     your network investigation''')

    parser.add_argument('-p', '--pcap_location',
                        help='The location of the Pcap for analysis', required=True)
    parser.add_argument('-2', '--layer_2',
                        help='view the layer 2 network scheme', required=False, action='store_true')
    parser.add_argument('-3', '--layer_3',
                        help='view the layer 3 network scheme', required=False, action='store_true')
    parser.add_argument('-dap', '--detect_arppoisoning',
                        help='detect for arp poisoning attacks', required=False, action='store_true')
    parser.add_argument('-dda', '--detect_dosattack',
                        help='detect for dos attacks / traffic load', required=False, action='store_true')
    parser.add_argument('-cdp', '--detect_cdpmapping',
                        help='detect for cdp spoofing / display all cdp queries ', required=False, action='store_true')
    parser.add_argument('-ddt', '--detect_dubtagging',
                        help='detect for double tagging in packets', required=False, action='store_true')
    parser.add_argument('-dhcp', '--display_DHCP',
                        help='displays the dhcp (discover, offers, acknowledge) in the pcap', required=False,
                        action='store_true')
    parser.add_argument('-tcps', '--tcp_scan',
                        help='checks for possible tcp connect scans (doesnt always work for sweep attacks)',
                        required=False, action='store_true')
    parser.add_argument('-ports', '--port_scan',
                        help='checks for possible tcp port scan', required=False, action='store_true')
    parser.add_argument('-r', '--output_report_path',
                        help='Generate a report to specified path', required=False)   
    args = vars(parser.parse_args())

    # Read the pcap
    packets = PcapReader()
    packets.read(args["pcap_location"])

    # declare the objects
    scheme = NetScheme()
    attacks = AttackDetect()
    learn = Machine_Learning()
    report = ReportEngine()

    # run the different attributes

    # layer 2 scheme
    if args["layer_2"]:
        packets.listarps()
        scheme.creategraph_layer2(packets.listhosts(layer=2), packets.whohas, packets.isat)

    # layer 3 scheme
    if args["layer_3"]:
        scheme.creategraph_layer3(packets.listhosts(layer=3), packets.listconvs())
        # scheme.creategraph_layer3(packets.listhosts(layer=3),packets.sessions)

        # for session in packets.sessions:
        #      print(session)
        # print(["ARP 192.168.1.111 > 192.168.1.1"])

    # arp poisoning detection
    if args["detect_arppoisoning"]:
        packets.listarps()
        attacker_dict = attacks.arppoisoning(packets.isat)
        if(len(attacker_dict) > 0):
            for attacker in attacker_dict.keys():
                report._add_report_row("Arp Poisoning",f'{attacker} Spoofed these MAC Addresses: {attacker_dict[attacker]}','detected')
        else:
            report._add_report_row("Arp Poisoning",'','not_detected')
    # dos detection visualisation
    if args["detect_dosattack"]:
        learn.Dos_table(packets.packets)
        learn.Dos_visual()

    # cdp detection
    if args["detect_cdpmapping"]:
        cdp_convs, cdp_attack_dict = attacks.cdp_mapping(packets.packets)
        if len(cdp_attack_dict) > 0:
            for cdp_attacker in cdp_attack_dict.keys():
                report._add_report_row('CDP Mapping',f'Source MAC {cdp_attacker} has suspicius CDP packet rate of {cdp_attack_dict[cdp_attacker]} ','detected')
                scheme.cdp_display(cdp_convs)
        else:
                report._add_report_row('CDP Mapping','','not_detected')
    # double tagging
    if args["detect_dubtagging"]:
        attacker_dict = packets.doubletag()
        if len(attacker_dict) > 0:
            for attacker in attacker_dict.keys():
                report._add_report_row('VLAN Double Tagging',f'{attacker} made a double tag attack using {attacker_dict[attacker]}','detected')
          
        else:
                report._add_report_row('VLAN Double Tagging','','not_detected')

    # display DHCP requests
    if args["display_DHCP"]:
        req, off, ack = packets.dhcp_detection()
        scheme.DHCP_plot(req, off, ack)

    # will detect and alert in case of tcp connect scan
    #if args["tcp_scan"]:
    #   attacks.tcp_scan(packets.tcp_scan(), packets.packets)
        # scanned, if_scanned = attacks.tcp_scan(packets.tcp_scan(), packets.packets)

        # if( if_scanned):
        #    attacks.scan_type(packets.packets, scanned)

    # will detect and alert in case of tcp generic port scan
    if args["port_scan"]:
        result = attacks.generic_tcp_port_scan(packets.tcp_scan(), packets.packets)
        if result[1]:
            for attacker in result[0].keys():
                report._add_report_row('Generic port Scan',f'{attacker} made a port scan attack using 500+ different ports on {result[0][attacker]}','detected')
        else:
            report._add_report_row('Generic port Scan','','not_detected')
            
    if args['output_report_path']:
        report._generate_report(args['output_report_path'])


if __name__ == "__main__":
    main()
