#IMPORTS
from scapy.all import *
from PcapReader import PcapReader
import networkx as nx
from NetScheme import NetScheme
from AttackDetect import AttackDetect
import argparse
from Machine_Learning import Machine_Learning

def main():
    # Create the parser
    parser = argparse.ArgumentParser(prog='data_shark.py',
                                    description='''Data-Shark a network forensics tool aimed
                                    at helping you detect and view all the needed data for
                                     your network investigation''')
    
    parser.add_argument('-p','--pcap_location', help='The location of the Pcap for analysis', required=True)
    parser.add_argument('-2','--layer_2', help='view the layer 2 network scheme', required=False, action='store_true')
    parser.add_argument('-3','--layer_3', help='view the layer 3 network scheme', required=False,action='store_true')
    parser.add_argument('-dap','--detect_arppoision', help='detect for arp posioning attacks', required=False, action='store_true')
    parser.add_argument('-dda','--detect_dosattack', help='detect for dos attacks / traffic load', required=False, action='store_true')
    parser.add_argument('-cdp','--detect_cdpmapping', help='detect for cdp spoofing/ display all cdp queries ', required=False, action='store_true')
    parser.add_argument('-dut','--detect_dubtagging', help='detect for double tagging in packets', required=False, action='store_true')
    parser.add_argument('-dhcp','--display_DHCP', help='displays the dhcp (dicover, offers, acknowledge) in the pcap', required=False, action='store_true')
    parser.add_argument('-tcps','--tcp_scan', help='checks for possible tcp connect scans (doesnt always work for sweep attacks)', required=False, action='store_true')
    

    args = vars(parser.parse_args())
    
    # Read the pcap
    packets = PcapReader()
    packets.read(args["pcap_location"])

    # declear the objects
    scheme = NetScheme()
    attacks = AttackDetect()
    learn = Machine_Learning()

    
    #run the diffrent attrinutes
    # layer 2 scheme
    if(args["layer_2"]):
        packets.listarps()
        scheme.creategraph_layer2(packets.listhosts(layer=2),packets.whohas,packets.isat)

    # layer 3 scheme
    if (args["layer_3"]):
        scheme.creategraph_layer3(packets.listhosts(layer=3),packets.listconvs())

    # arp poisining detection
    if(args["detect_arppoision"]):
        packets.listarps()

        attacks.arpposioning(packets.isat)

    # dos detection visualsation
    if(args["detect_dosattack"]):
        learn.Dos_table(packets.packets)
        learn.Dos_visual()

    # cdp detection
    if(args["detect_cdpmapping"]):
        scheme.cdp_display(attacks.cdp_mapping(packets.packets))

    # double tagging
    if(args["detect_dubtagging"]):
        packets.doubletag()

    # display DHCP requests
    if(args["display_DHCP"]):
        req, off, ack = packets.dhcp_detection()
        scheme.DHCP_plot(req,off,ack)

    # will detect and alert in case of tcp connect scan
    if(args["tcp_scan"]):  
        scaneed, if_scnaed = attacks.tcp_scan(packets.tcp_scan(), packets.packets)
        #if( if_scnaed):
        #    attacks.scan_type(packets.packets, scaneed)


if __name__ == "__main__":
    main()