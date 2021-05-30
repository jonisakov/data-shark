# Import
from scapy.layers.inet import IP
from scapy.all import *
# import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import datetime


class DOS_Detect(object):

    def __init__(self):
        self.dt = pd.DataFrame()

    def Dos_table(self, packets):
        """
        Dos_table(packets) -> pandas excel of packet_num, size, time
        will receive the packets of the pcap and return the pandas format,
        in order to detect DOS attacks or visualise all traffic.
        """

        # number = []
        size = []
        times = []
        for PACKET in packets:
            if PACKET.haslayer(IP):
                size.append(len(PACKET))
                times.append(datetime.datetime.fromtimestamp(PACKET.time))

        data = {"size": size, "time": times}
        self.dt = pd.DataFrame(data, columns=['size', 'time'])

        self.dt = self.dt.groupby('time')["size"].sum()

    def Dos_visual(self):
        """
        will display the packet load in an easy to see way requires the Dos_table to be run before hand
        """

        # gca stands for 'get current axis'
        ax = plt.gca()

        self.dt.plot(kind='area', x='time', y='bits', ax=ax)

        plt.get_current_fig_manager().set_window_title('Dos visualization')

        plt.show()
