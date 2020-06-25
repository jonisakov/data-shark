#Import
from scapy.all import *
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import datetime


class Machine_Learning(object):
	
	def Dos_table(self, packets):
		"""
		Dos_table(packets) -> pandas excel of packet_num, size, time
		will recive the packets of the pcap and return the pandas format,
		in order to detect DOS attacks or visualiese all trafic.
		"""

		number = []
		size = []
		time = []
		for packet in packets:
			if(packet.haslayer(IP)):
				size.append(len(packet))
				time.append(datetime.datetime.fromtimestamp(packet.time))
		
		data = {"size" : size ,"time" : time}
		self.dt = pd.DataFrame(data, columns = ['size', 'time'])
		
		self.dt = self.dt.groupby('time')["size"].sum()

	def Dos_visual(self):
		"""
		will display the packet load in an easy to see way
		requires the Dos_table to be run before hand
		"""
		
		# gca stands for 'get current axis'
		ax = plt.gca()

		self.dt.plot(kind= 'area',x='time',y='bits',ax=ax)

		plt.show()