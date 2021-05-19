import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


class NetScheme(object):
    """this class helps us to create a network scheme"""

    @staticmethod
    def creategraph_layer3(addresses, convs):
        """
        creates and displays a layer graph
        creategraph_layer3(addresses, convs) -> a display og the layer 3 conversations
        addresses - the layer 3 address list, will be converted to node
        convs     - the layer 3 list of [src,dist,dport]
        """
        G = nx.DiGraph()
        i = 0
        nodedict = {}
        edgedict = {}
        reverselookupdict = {}
        for address in addresses:
            G.add_node(i)
            nodedict[i] = address
            reverselookupdict[address] = i
            i = i + 1

        for conv in convs:
            G.add_edge(reverselookupdict[conv[0]], reverselookupdict[conv[1]])
            edgedict[(reverselookupdict[conv[0]], reverselookupdict[conv[1]])] = conv[2]

        pos = nx.spring_layout(G)
        nx.draw(G, pos, labels=nodedict, with_labels=True)
        print(edgedict)
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edgedict, font_color='red')
        plt.show()

    # def creategraph_layer3(self, addresses, sessions):
    #     """
    #     creates and displays a layer graph
    #     creategraph_layer3(addresses, convs) -> a display og the layer 3 conversations
    #     addresses - the layer 3 address list, will be converted to node
    #     convs     - the layer 3 list of [src,dist,dport]
    #     """
    #     G = nx.DiGraph()
    #     i = 0
    #     nodedict = {}
    #     edgedict = {}
    #     reverselookupdict = {}
    #     for address in addresses:
    #         G.add_node(i)
    #         nodedict[i] = address
    #         reverselookupdict[address] = i
    #         i = i + 1
    #
    #     for session in sessions:
    #
    #         if session.split(" ")[0] != 'IPv6':
    #             source = session.split(" ")[1].split(":")[0]
    #             dest = session.split(" ")[3].split(":")[0]
    #
    #             try:
    #                 dport = session.split(" ")[3].split(":")[1]
    #             except:
    #                 dport = session.split(" ")[0] # No port in session
    #
    #             G.add_edge(reverselookupdict[source] ,reverselookupdict[dest])
    #             edgedict[(reverselookupdict[source], reverselookupdict[dest])] = dport
    #
    #     pos = nx.spring_layout(G)
    #     nx.draw(G, pos, labels=nodedict, with_labels=True)
    #     print(edgedict)
    #     nx.draw_networkx_edge_labels(G, pos, edge_labels=edgedict, font_color='red')
    #     plt.show()

    @staticmethod
    def creategraph_layer2(macs, whohas, isat):
        """
        creategraph_layer2(macs, whohas,isat) ---> will display a graph of all the arp questions

        macs - list of all mac addresses in the pcap (obtained from the pcapreader class)
        whohas -  all the arp requests for who has (obtained from the pcapreader class)
        isat - all the answers in arp form (obtained from the pcapreader class)
        """
        G = nx.DiGraph()
        i = 0
        nodedict = {}
        whodict = {}
        isatdict = {}
        reverselookupdict = {}
        for mac in macs:
            G.add_node(i)
            nodedict[i] = mac
            reverselookupdict[mac] = i
            i = i + 1
        for q in whohas:
            G.add_edge(reverselookupdict[q[0]], reverselookupdict[q[1]])
            whodict[(reverselookupdict[q[0]], reverselookupdict[q[1]])] = q[3]
        for a in isat:
            G.add_edge(reverselookupdict[a[1]], reverselookupdict[a[0]])
            isatdict[(reverselookupdict[a[1]], reverselookupdict[a[0]])] = a[2]

        pos = nx.spring_layout(G)
        plt.legend(loc="upper left")

        # create the node/edge and name them
        nx.draw_networkx_edge_labels(G, pos, edge_labels=whodict, font_color='red')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=isatdict, font_color='blue')
        nx.draw_networkx(G, pos, labels=nodedict)

        # create the legend
        legend_elements = [Line2D([0], [0], color='r', lw=4, label='who has'),
                           Line2D([0], [0], color='b', lw=4, label='is at',
                                  markerfacecolor='g', markersize=15)]

        plt.legend(handles=legend_elements)

        plt.show()

    @staticmethod
    def cdp_display(queries):
        """
        cdp_display(self,queries) -> graph of al cdp queries made in the pcap
        will display with network x all the cdp made in the pcap file
        """

        G = nx.DiGraph()
        i = 0
        # query = {}
        nodedict = {}
        ips = {}
        reverselookupdict = {}

        for q in queries:
            G.add_node(i)
            nodedict[i] = q[0]
            reverselookupdict[q[0]] = i
            i = i + 1
            G.add_node(i)
            nodedict[i] = q[1]
            reverselookupdict[q[1]] = i
            i = i + 1
        for q in queries:
            G.add_edge(reverselookupdict[q[0]], reverselookupdict[q[1]])
            ips[(reverselookupdict[q[0]], reverselookupdict[q[1]])] = q[2]

        pos = nx.spring_layout(G)
        plt.legend(loc="upper left")

        # create the node/edge and name them
        nx.draw_networkx_edge_labels(G, pos, edge_labels=ips)
        nx.draw_networkx(G, pos, labels=nodedict)
        plt.show()

    @staticmethod
    def DHCP_plot(req=None, off=None, ack=None):
        """
        will plot the dhcp requests made in the pcap and display them i a color coded way
        """
        if ack is None:
            ack = []
        if off is None:
            off = []
        if req is None:
            req = []
        G = nx.DiGraph()
        i = 0
        # query = {}
        nodedict = {}
        edges = {}
        color_map = []
        reverselookupdict = {}

        # add the requests node
        G.add_node(i)
        nodedict[i] = 'FF:FF:FF:FF:FF:FF'
        reverselookupdict['FF:FF:FF:FF:FF:FF'] = i
        color_map.append("red")
        i += 1
        for address in req:
            G.add_node(i)
            nodedict[i] = address
            reverselookupdict[address] = i
            color_map.append("red")
            i += 1
        for address in req:
            G.add_edge(reverselookupdict[address], reverselookupdict['FF:FF:FF:FF:FF:FF'])
            # edges[(reverselookupdict[address],reverselookupdict['FF:FF:FF:FF:FF:FF'])] = address

        # add the offer nodes
        for address in off:
            G.add_node(i)
            nodedict[i] = address[1]
            reverselookupdict[address[1]] = i
            color_map.append("blue")
            i += 1
            G.add_node(i)
            nodedict[i] = address[2]
            reverselookupdict[address[2]] = i
            color_map.append("blue")
            i += 1
        for address in off:
            G.add_edge(reverselookupdict[address[1]], reverselookupdict[address[2]])
            edges[reverselookupdict[address[1]], reverselookupdict[address[2]]] = address[0]

        # add the DHCPACK nodes
        for address in ack:
            G.add_node(i)
            nodedict[i] = address[0]
            reverselookupdict[address[0]] = i
            color_map.append("green")
            i += 1
            G.add_node(i)
            nodedict[i] = address[1]
            reverselookupdict[address[1]] = i
            color_map.append("green")
            i += 1
        for address in ack:
            G.add_edge(reverselookupdict[address[0]], reverselookupdict[address[1]])

        print("""
            Labels:
            Red - requests / discover nodes
            Blue - offers / acknowledge nodes
            Green - DHCPACK nodes
            """)

        # display the graph
        pos = nx.spring_layout(G)
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edges)
        nx.draw_networkx(G, pos, node_color=color_map, labels=nodedict, with_labels=True)
        plt.legend(fancybox=True, framealpha=1, shadow=True, borderpad=1)
        plt.show()