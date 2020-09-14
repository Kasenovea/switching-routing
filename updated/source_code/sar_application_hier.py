from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches 
import networkx as nx
import json
import logging
import struct
import collections
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath
from collections import deque


# Packet Classification parameters
SRC_IP = 0
DST_IP = 1
PROTO  = 2
SPORT  = 3
DPORT  = 4
ACTION = 5

# IP lookup parameters
IP     = 0
SUBNET = 1
DPID   = 2

# Topologies
TOPO = 2


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}
	
	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.no_of_nodes = 0
		self.no_of_links = 0		
		self.datapaths = []
		self.switch_id = []
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.i=0
		
		# Packet Classification initial parameters
		
		self.classify = {}
		self.classify["r1"] = ["195.3.0.1","128.128.0.1","6","1234","1234","allow"]
		self.classify["r2"] = ["128.128.0.1","195.0.0.1","6","123","77","allow"]
		self.classify["r3"] = ["197.0.0.1","128.128.0.1","1","19","1234","allow"]
		self.classify["r4"] = ["128.128.0.1","197.0.0.1","1","*","*","allow"]
		self.classify["r5"] = ["128.128.0.1","128.128.0.1","1","*","123","allow"]
		self.classify["r6"] = ["128.128.0.1","197.0.0.1","1","*","*","allow"]
		self.classify["r7"] = ["128.128.0.1","128.128.0.1","1","*","*","allow"]
		self.classify["r8"] = ["195.0.0.1","197.0.0.1","1","77","1234","allow"]
		self.classify["r9"] = [" 195.0.0.1"," 154.128.0.1","1","77","1234","allow"]
		self.classify["r10"] = ["195.0.0.1","154.128.0.1","1","77","1234","allow"]
		self.classify["r11"] = ["195.0.0.1","154.0.0.1","1","77","1234","allow"]
		self.classify["r12"] = ["195.0.0.1","195.0.0.2","1","*","*","allow"]
		

		self.classify["r13"] = ["195.0.0.1","192.168.0.2","6","*","*","allow"]
		self.classify["r14"] = ["195.0.0.1","192.168.0.1","6","*","*","allow"]
		self.classify["r15"] = ["195.0.0.1","192.168.0.1","1","*","*","allow"]
		self.classify["r16"] = ["195.0.0.1","128.128.0.1","15","66","77","allow"]
		self.classify["r17"] = ["195.0.0.1","192.170.0.1","6","*","*","allow"]
		self.classify["r18"] = ["195.0.0.1","192.170.0.1","1","*","*","allow"]	
		self.classify["r19"] = ["195.0.0.1","192.170.0.2","6","*","*","allow"]
		self.classify["r20"] = ["195.0.0.1","192.170.0.2","1","*","*","allow"]
		self.classify["r21"] = ["195.0.0.1","192.171.0.1","6","*","*","allow"]
		self.classify["r22"] = ["195.0.0.1","192.171.0.1","1","*","*","allow"]
		self.classify["r23"] = ["195.0.0.1","192.172.0.1","6","*","*","allow"]
		self.classify["r24"] = ["195.0.0.1","192.172.0.1","1","*","*","allow"]
		self.classify["r25"] = ["195.0.0.1","192.172.0.2","6","*","*","allow"]
		self.classify["r26"] = ["195.0.0.1","192.172.0.2","1","*","*","allow"]
		self.classify["r27"] = ["195.0.0.1","192.173.0.1","6","*","*","allow"]
		self.classify["r28"] = ["195.0.0.1","192.173.0.1","1","*","*","allow"]
		self.classify["r29"] = ["195.0.0.2","195.0.0.1","6","*","*","allow"]
		self.classify["r30"] = ["195.0.0.2","195.0.0.1","1","*","*","allow"]
		self.classify["r31"] = ["195.0.0.2","128.128.0.1","6","*","*","allow"]
		self.classify["r32"] = ["195.0.0.2","128.128.0.1","1","*","*","allow"]
		self.classify["r33"] = ["195.0.0.2","154.128.0.1","6","*","*","allow"]
		self.classify["r34"] = ["195.0.0.2","154.128.0.1","1","*","*","allow"]
		self.classify["r35"] = ["195.0.0.2","154.128.0.2","6","*","*","allow"]
		self.classify["r36"] = ["195.0.0.2","154.128.0.2","1","*","*","allow"]
		self.classify["r37"] = ["195.0.0.2","197.160.0.1","6","*","*","allow"]
		self.classify["r38"] = ["195.0.0.2","197.160.0.1","1","*","*","allow"]
		self.classify["r39"] = ["195.0.0.2","192.168.0.1","6","*","*","allow"]
		self.classify["r40"] = ["195.0.0.2","192.168.0.1","1","*","*","allow"]
		self.classify["r41"] = ["195.0.0.2","192.168.0.2","6","*","*","allow"]
		self.classify["r42"] = ["195.0.0.2","192.168.0.2","1","*","*","allow"]
		self.classify["r43"] = ["195.0.0.2","192.169.0.1","6","*","*","allow"]
		self.classify["r44"] = ["195.0.0.2","192.169.0.1","1","*","*","allow"]
		self.classify["r45"] = ["195.0.0.2","192.170.0.1","6","*","*","allow"]
		self.classify["r46"] = ["195.0.0.2","192.170.0.1","1","*","*","allow"]
		self.classify["r47"] = ["195.0.0.2","192.170.0.2","6","*","*","allow"]
		self.classify["r48"] = ["195.0.0.2","192.170.0.2","1","*","*","allow"]
		self.classify["r49"] = ["195.0.0.2","192.171.0.1","6","*","*","allow"]
		self.classify["r50"] = ["195.0.0.2","192.171.0.1","1","*","*","allow"]
		self.classify["r51"] = ["195.0.0.2","192.172.0.1","6","*","*","allow"]
		self.classify["r52"] = ["195.0.0.2","192.172.0.1","1","*","*","allow"]
		self.classify["r53"] = ["195.0.0.2","192.172.0.2","6","*","*","allow"]
		self.classify["r54"] = ["195.0.0.2","192.172.0.2","1","*","*","allow"]
		self.classify["r55"] = ["195.0.0.2","192.173.0.1","6","*","*","allow"]

 
		self.counters = {} 
		self.counters["r1"] = 0                           
		self.counters["r2"] = 0                           
		self.counters["r3"] = 0                           
		self.counters["r4"] = 0                           
		self.counters["r5"] = 0                           
		self.counters["r6"] = 0                           
		self.counters["r7"] = 0                           
		self.counters["r8"] = 0  
		self.counters["r9"] = 0                           
		self.counters["r10"] = 0                           
		self.counters["r11"] = 0  
		self.counters["r12"] = 0 
		self.counters["r13"] = 0
		self.counters["r14"] = 0
		self.counters["r15"] = 0
		self.counters["r16"] = 0
		self.counters["r17"] = 0
		self.counters["r18"] = 0
		self.counters["r19"] = 0
		self.counters["r20"] = 0
		self.counters["r21"] = 0
		self.counters["r22"] = 0
		self.counters["r23"] = 0
		self.counters["r24"] = 0
		self.counters["r25"] = 0
		self.counters["r26"] = 0
		self.counters["r27"] = 0
		self.counters["r28"] = 0
		self.counters["r29"] = 0
		self.counters["r30"] = 0
		self.counters["r31"] = 0
		self.counters["r32"] = 0
		self.counters["r33"] = 0
		self.counters["r34"] = 0
		self.counters["r35"] = 0
		self.counters["r36"] = 0
		self.counters["r37"] = 0
		self.counters["r38"] = 0
		self.counters["r39"] = 0
		self.counters["r40"] = 0
		self.counters["r41"] = 0
		self.counters["r42"] = 0
		self.counters["r43"] = 0
		self.counters["r44"] = 0
		self.counters["r45"] = 0
		self.counters["r46"] = 0
		self.counters["r47"] = 0
		self.counters["r48"] = 0
		self.counters["r49"] = 0
		self.counters["r50"] = 0
		self.counters["r51"] = 0
		self.counters["r52"] = 0
		self.counters["r53"] = 0
		self.counters["r54"] = 0
		self.counters["r55"] = 0                     
		#self.counters["r5"] = 0       
		
		if TOPO == 1:			
			self.switch = {}
			self.switch["195.0.0.254"  ] = ["195.0.0.254","8","1"] 
			self.switch["128.128.0.254"] = ["128.128.0.254","12","2"] 
			self.switch["154.128.0.254"] = ["154.128.0.254","16","3"] 

			self.lookup = {}
			self.lookup["195.0.0.1"]   = "195.0.0.254"
			self.lookup["195.0.0.2"]   = "195.0.0.254"
			self.lookup["128.128.0.1"] = "128.128.0.254"
			self.lookup["128.128.0.2"] = "128.128.0.254"
			self.lookup["154.128.0.1"] = "154.128.0.254"
			self.lookup["154.128.0.2"] = "154.128.0.254"
			
			self.ip_to_mac = {}
			self.ip_to_mac["195.0.0.1"]   = "00:00:00:00:00:01"
			self.ip_to_mac["195.0.0.2"]   = "00:00:00:00:00:02"
			self.ip_to_mac["128.128.0.1"] = "00:00:00:00:00:03"
			self.ip_to_mac["128.128.0.2"] = "00:00:00:00:00:04"
			self.ip_to_mac["154.128.0.1"] = "00:00:00:00:00:05"
			self.ip_to_mac["154.128.0.2"] = "00:00:00:00:00:06"
		
		elif TOPO == 2:
			self.switch = {}
			self.switch["195.0.0.254"  ]   = ["195.0.0.254","8","1"] 
			self.switch["128.128.0.254"]   = ["128.128.0.254","12","2"] 
			self.switch["154.128.0.254"]   = ["154.128.0.254","16","3"] 
			self.switch["197.160.0.254"]   = ["197.160.0.254","24","4"]
			self.switch["192.168.0.254"]   = ["192.168.0.254","24","5"]	
			self.switch["192.169.0.254"]  = ["192.169.0.254","24","6"]
			self.switch["192.170.0.254"]  = ["192.170.0.254","24","7"]

			self.lookup = {}
			self.lookup["195.0.0.1"]     = "195.0.0.254"
			self.lookup["195.0.0.2"]     = "195.0.0.254"
			self.lookup["128.128.0.1"]   = "128.128.0.254"
			self.lookup["154.128.0.1"]   = "154.128.0.254"
			self.lookup["197.160.0.1"]   = "197.160.0.254"
			self.lookup["192.168.0.1"]   = "192.168.0.254"
			self.lookup["192.169.0.1"]  = "192.169.0.254"
			self.lookup["192.170.0.1"]  = "192.170.0.254"

			
			self.ip_to_mac = {}
			self.ip_to_mac["195.0.0.1"]     = "00:00:00:00:00:01"
			self.ip_to_mac["195.0.0.2"]     = "00:00:00:00:00:02"
			self.ip_to_mac["128.128.0.1"]   = "00:00:00:00:00:03"
			self.ip_to_mac["154.128.0.1"]   = "00:00:00:00:00:04"
			self.ip_to_mac["197.160.0.1"]   = "00:00:00:00:00:05"
			self.ip_to_mac["192.168.0.1"]   = "00:00:00:00:00:06"
			self.ip_to_mac["192.169.0.1"]  = "00:00:00:00:00:07"
			self.ip_to_mac["192.170.0.1"]  = "00:00:00:00:00:08"			

	
		
		
	def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
		if opcode == 1:
			targetMac = "00:00:00:00:00:00"
			targetIp = dstIp
		elif opcode == 2:
			targetMac = dstMac
			targetIp = dstIp

		e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
		p = Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()

		actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath,
			buffer_id=0xffffffff,
			in_port=datapath.ofproto.OFPP_CONTROLLER,
			actions=actions,
			data=p.data)
		datapath.send_msg(out)

		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		msg = ev.msg
		self.datapaths.append(msg.datapath)
		self.switch_id.append(msg.datapath_id)
		
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
		
	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
        
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']		

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
			return
		dst = eth.dst
		src = eth.src
		
		dpid_src = datapath.id
		
		# TOPOLOGY DISCOVERY------------------------------------------
		
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]		
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		# print links
		
		# MAC LEARNING-------------------------------------------------
		
		self.mac_to_port.setdefault(dpid_src, {})
		self.mac_to_port.setdefault(src, {})
		self.port_to_mac.setdefault(dpid_src, {})
		self.mac_to_port[dpid_src][src] = in_port	
		self.mac_to_dpid[src] = dpid_src
		self.port_to_mac[dpid_src][in_port] = src
		self.logger.info("Packet in the controller from switch: %s", dpid_src)
		#print self.mac_to_port
		
		# HANDLE ARP PACKETS--------------------------------------------
		
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			arp_packet = pkt.get_protocol(arp.arp)
			arp_dst_ip = arp_packet.dst_ip
			arp_src_ip = arp_packet.src_ip
			# self.logger.info("ARP packet from switch: %s source IP: %s destination IP: %s from port: %s", dpid_src, arp_src_ip, arp_dst_ip, in_port)
			# self.logger.info("ARP packet from switch: %s source MAC: %s destination MAC:%s from port: %s", dpid_src, src, dst, in_port)
			
			if arp_dst_ip in self.ip_to_mac:
				if arp_packet.opcode == 1:
					# send arp reply (SAME SUBNET)
					dstIp = arp_src_ip
					srcIp = arp_dst_ip
					dstMac = src
					srcMac = self.ip_to_mac[arp_dst_ip]
					outPort = in_port
					opcode = 2 # arp reply packet
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
			else:
				if arp_packet.opcode == 1:
					# send arp reply (GATEWAY)
					dstIp = arp_src_ip
					srcIp = arp_dst_ip
					dstMac = src
					srcMac = self.port_to_mac[dpid_src][in_port]
					outPort = in_port
					opcode = 2 # arp reply packet
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
		
		# HANDLE IP PACKETS----------------------------------------------- 	
		
		ip4_pkt = pkt.get_protocol(ipv4.ipv4)
		if ip4_pkt:
			src_ip = ip4_pkt.src
			dst_ip = ip4_pkt.dst
			proto  = str(ip4_pkt.proto)
			sport = "0"
			dport = "0" 
			if proto == "6":
				tcp_pkt = pkt.get_protocol(tcp.tcp)
				sport = str(tcp_pkt.src_port)
				dport = str(tcp_pkt.dst_port)
			   
			if proto == "17":
				udp_pkt = pkt.get_protocol(udp.udp)
				sport = str(udp_pkt.src_port)
				dport = str(udp_pkt.dst_port)
				
			self.logger.info("Packet from the switch: %s, source IP: %s, destination IP: %s, From the port: %s", dpid_src, src_ip, dst_ip, in_port)
#############################################################################################################################			
			





























			# PACKET CLASSIFICATION FUNCTION: it returns action: "allow" or "deny"
			#here we call our tree and function which were defined below of script 
			#class TREE and NODE are out of Class SIMPLEswitch
			#if here put code of call , the program will be called iteratively

			action_rule = self.linear_classification(src_ip, dst_ip, proto, sport, dport)
			#action_rule = "allow"	
			
			##############################################
			#
			
			############################################## here handle F1 field source ip ################################
			#here actual info of packet ,
			print "proto of pkt", proto
			print "sport of pkt", sport
			print "dport of pkt", dport

			


			
			


			

				



			

			#here we convert src_ip into binary and put them in vector nod[] we need it for further computation
			nod=[]
			for rule in self.classify:
				k=fromIPtoBinary_1(self.classify[rule][SRC_IP])
				nod.append(k)
					
			#below, in creation tree we put all brahches in list and after handle them in order to create tree
			f1=Tree()
			i=0
			while i<=len(nod[1]):
				k=0
				tupl=[]
				while k<len(nod):
					
					tupl.append(nod[k][:i])
					
					
					k+=1
				#this checks similar branches and delete the duplicates 	
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					#here we assign nodes 
					f1.add_node(str(ke))
				

				i+=1

			#here we assign rules accordinf with Hierarchical tree algorithm
			for rule in self.classify:
				f1.add_rule(fromIPtoBinary(self.classify[rule][SRC_IP]),0,rule,None)
			
			
						


			#this is commented PrintTree function , just  to check the tree decommnet it and run
			
			#f1.print_tree(f1.root)

			
			#Here we search based on binary version of src_ip best prefix match in the Tree
			ff=f1.finding_prefix_src("128.128.0.1",f1.root,0)
			
			
			#here we see best prefix match
			print "\n\n\nBest prefix match for SRC_IP:",ff
			
			


			
					
			#here we convert matrix into vector and clean duplicates ,bcz duplicates occur during the iteration of finding prefix
			li = list(i for j in source_all for i in j)
			f1_all=list(dict.fromkeys(li))
			print "All rules while searching prefix in SRC_IP",f1_all
			

			
			


################################## DST-IP handlin#######################################

		#In this section all codes are the same as SRC_IP section 

			nod2=[]
			for rule in self.classify:
				k=fromIPtoBinary_1(self.classify[rule][DST_IP])
				nod2.append(k)

			f2=Tree()
			i=0
			while i<=len(nod2[1]):
				k=0
				tupl=[]
				while k<len(nod2):
					
					tupl.append(nod2[k][:i])
					
					
					k+=1
				#this checks similar branches and delete the duplicates 	
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					#here we assign nodes 
					f2.add_node(str(ke))
				

				i+=1
			####addin rule for F2 field 
			
			for rule in self.classify:
				f2.add_rule(fromIPtoBinary(self.classify[rule][DST_IP]),0,rule,None)

			
			
				
			#f2.print_tree(f2.root)
			ff2=f2.finding_prefix_dst(dst_ip,f2.root,0)
			print "\n\nBest prefix match DST_IP:",ff2
			
			li1 = list(i for j in dst_all for i in j)
			f2_all=list(dict.fromkeys(li1))
			

			
			
			
		
			print "All rule while searching best prefix in DST-IP:",f2_all

			
			
#############################################handling filed 3 proto######################################################
		
			#this is binary version of proto of packet
			bin_proto=str(bin(int(proto))[2:])
			
			#Here we convert all proto in rules into binary versions and append them in vector prep[]
			prep=[]
			for i in self.classify:
				prt=str(bin(int(self.classify[i][PROTO]))[2:])
				prep.append(prt)
			
			

			
			#here we "fix" binary version:we align them and made them similiar size it is neccesary to create Tree
			chunk3=[]
			for i in prep:
				chunk3.append(i.ljust(len( max(prep,key=len)),'0'))
			
			#Here we create third tree for Proto 
			f3=Tree()
			
			
			i=0
			while i<=len(chunk3[1]):
				k=0
				tupl=[]
				while k<len(chunk3):
					
					tupl.append(chunk3[k][:i])
					
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					
					#here we assign nodes
					f3.add_node(str(ke))
					
				

				i+=1


			
			for rule in sorted(self.classify):
				
				f3.add_rule(str(bin(int(self.classify[rule][PROTO]))[2:]),0,rule,None)
			
			
			#here we use finiding prefix func in order to find prefix for 
			
			ff3=f3.finding_prefix_one(proto,f3.root,0)
			
			print "\n\nBest prefix match PROTO:", ff3
			

			# as we have mentioned ,here also convertion matrix into vector and deletion the duplicates
			li2 = list(i for j in sort for i in j)
			f3_all=list(dict.fromkeys(li2))
			

			
			
			
		
			print "All rule while searching best prefix in PROTO:",f3_all

			




################################## handlin source port Field 4#####################################################
			#here we put all s_port in to vector for further computation 
			all_sport=[]
			
			for i in self.classify:
				
				all_sport.append(self.classify[i][SPORT])

			#here we clean duplicates	
			all_sport=list(dict.fromkeys(all_sport))
			

			
			#here we sort and append into data[ ] only non star=="*" source port , bcz "star" source port goes to root of the Tree 
			data=[]
			
			for i in all_sport:
				if i!="*":
					
					k=str(bin(int(i))[2:])
					data.append(k)
				
			
			#Here also we align all branches, we alligned them with zeros, and it doesnt impact to correctness of Tree
			same_sport=[]
			for i in data:
				
				same_sport.append(i.ljust(len( max(data,key=len)),'0'))
			
			#Here we create tree for source port and assign nodes
			f4=Tree()
			i=0
			while i<=len(same_sport[1]):
				k=0
				tupl=[]
				while k<len(same_sport):
					
					tupl.append(same_sport[k][:i])
					
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					
					f4.add_node(str(ke))
					
				
				i+=1
			
			for rule in sorted(self.classify):
				
				if self.classify[rule][SPORT]!="*":
					
					f4.add_rule(str(bin(int(self.classify[rule][SPORT]))[2:]),0,rule,None)
				else:
					
					f4.add_rule("",0,rule,None)
			

			
			
			#f4.print_tree(f4.root)

			ff4=f4.finding_prefix_sport(sport,f4.root,0)
			
			print "\n\nBest prefix match SPORT:", ff4
			li3 = list(i for j in sport_all for i in j)
			f4_all=list(dict.fromkeys(li3))
			

			
			
			
		
			print "All rule while searching best prefix in SPORT:",f4_all
			

			





##########################################handling field 5############# handling destination port#################################


			all_dport=[]
			
			for i in self.classify:
				
				all_dport.append(self.classify[i][DPORT])

			#here we clean duplicates	
			all_dport=list(dict.fromkeys(all_dport))
			

			
			#here we sort and append into data[ ] only non star=="*" source port , bcz "star" source port goes to root of the Tree 
			data1=[]
			
			for i in all_dport:
				if i!="*":
					
					k=str(bin(int(i))[2:])
					data1.append(k)
				
			
			#Here also we align all branches, we alligned them with zeros, and it doesnt impact to correctness of Tree
			same_dport=[]
			for i in data:
				
				same_dport.append(i.ljust(len( max(data1,key=len)),'0'))
			
			#Here we create tree for source port and assign nodes
			f5=Tree()
			i=0
			while i<=len(same_dport[1]):
				k=0
				tupl=[]
				while k<len(same_dport):
					
					tupl.append(same_dport[k][:i])
					
					
					k+=1
				tupl=list(dict.fromkeys(tupl))
				for ke in tupl:
					
					f5.add_node(str(ke))
					
				
				i+=1
			
			for rule in sorted(self.classify):
				
				if self.classify[rule][DPORT]!="*":
					
					f5.add_rule(str(bin(int(self.classify[rule][DPORT]))[2:]),0,rule,None)
				else:
					
					f5.add_rule("",0,rule,None)
			

			
			
			#f4.print_tree(f4.root)

			ff5=f5.finding_prefix_dport(dport,f5.root,0)
			
			print "\n\nBest prefix match DPORT:", ff5
			li4 = list(i for j in dport_all for i in j)
			f5_all=list(dict.fromkeys(li4))
			

			
			
			
		
			print "All rule while searching best prefix in DPORT:",f5_all
			
####################################################################################################################################			
		#here we call function Hierarchical tree function
		
			ppp=self.hierarchical_classification(ff,f1_all,ff2,f2_all,ff3,f3_all,ff4,f4_all,ff5,f5_all)




















			action_rule="deny"

			if action_rule == "allow":			
				# IP LOOKUP FUNCTION: it is zero if it didn't find a solution
				destination_switch_IP = self.linear_search(dst_ip)
				
				if destination_switch_IP != "0":
					datapath_dst = get_datapath(self,int(self.switch[destination_switch_IP][DPID]))
					dpid_dst = datapath_dst.id			
					self.logger.info(" --- Destination present on switch: %s", dpid_dst)
					
					# Shortest path computation
					path = nx.shortest_path(self.net,dpid_src,dpid_dst)
					self.logger.info(" --- Shortest path: %s", path)
					
					if len(path) == 1:
						In_Port = self.mac_to_port[dpid_src][src]
						Out_Port = self.mac_to_port[dpid_dst][dst]	
						actions_1 = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
						actions_2 = [datapath.ofproto_parser.OFPActionOutput(In_Port)]
						match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst)
						self.add_flow(datapath, 1, match_1, actions_1)

						actions = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
						data = msg.data
						pkt = packet.Packet(data)
						eth = pkt.get_protocols(ethernet.ethernet)[0]
						# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
						pkt.serialize()
						out = datapath.ofproto_parser.OFPPacketOut(
							datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
							actions=actions, data=pkt.data)
						datapath.send_msg(out)
						
						
					elif len(path) == 2:				
						path_port = self.net[path[0]][path[1]]['port']
						actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
						data = msg.data
						pkt = packet.Packet(data)
						eth = pkt.get_protocols(ethernet.ethernet)[0]
						eth.src = self.ip_to_mac[src_ip] 
						eth.dst = self.ip_to_mac[dst_ip] 
						# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
						pkt.serialize()
						out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
							actions=actions, data=pkt.data)
						datapath.send_msg(out)	
						
					elif len(path) > 2:
						# Add flows in the middle of the network path 
						for i in range(1, len(path)-1):							
							In_Port = self.net[path[i]][path[i-1]]['port']
							Out_Port = self.net[path[i]][path[i+1]]['port']
							dp = get_datapath(self, path[i])
							# self.logger.info("Matched OpenFlow Rule = switch: %s, from in port: %s, to out port: %s, source IP: %s, and destination IP: %s", path[i], In_Port, Out_Port, src_ip, dst_ip)
						
							actions_1 = [dp.ofproto_parser.OFPActionOutput(Out_Port)]
							match_1 = parser.OFPMatch(in_port=In_Port, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
							self.add_flow(dp, 1, match_1, actions_1)
						
						path_port = self.net[path[0]][path[1]]['port']
						actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
						data = msg.data
						pkt = packet.Packet(data)
						eth = pkt.get_protocols(ethernet.ethernet)[0]
						# change the mac address of packet
						eth.src = self.ip_to_mac[src_ip] 
						eth.dst = self.ip_to_mac[dst_ip] 
						# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
						pkt.serialize()
						out = datapath.ofproto_parser.OFPPacketOut(
						datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
							actions=actions, data=pkt.data)
						datapath.send_msg(out)

	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]		
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)		
		# print "**********List of links"
		# print self.net.edges()
        #for link in links_list:
	    #print link.dst
            #print link.src
            #print "Novo link"
	    #self.no_of_links += 1		

#-------------------------------------------------------------------------------------------------------
		
	def linear_search(self, dst_ip):
		self.logger.info(" --- IP address Lookup") 
		if dst_ip in self.lookup:
			destination_switch_IP = self.lookup[dst_ip]
			return destination_switch_IP
		else:
			destination_switch_IP = "0"
			return destination_switch_IP
	

	#here general function to handle prefixes and obtaion rule and ACTION
	def hierarchical_classification(self,ff,f1_all,ff2,f2_all,ff3,f3_all,ff4,f4_all,ff5,f5_all):
		action="deny"
		self.logger.info(" ========= Packet classification--Hierarchical-Tree==========")


		#here we need find common rule from all fields based on best prefixes,and further we check common rules for "fields-1" like backtracking
		if list(set(ff).intersection(ff2).intersection(ff3).intersection(ff4).intersection(ff5))!=[]:
			m1=list(set(ff).intersection(ff2).intersection(ff3).intersection(ff4).intersection(ff5))
			prior1=[]
			for i in m1:
				dec=int(i[1:])
				prior1.append(dec)

			rul=str("r"+str(min(prior1)))
			action=self.classify[rul][ACTION]
			self.logger.info(" ---- Packet matched rule-------- %s. Action is %s" % (rul, self.classify[rul][ACTION]))  
		
		elif list(set(ff).intersection(ff2).intersection(ff3).intersection(ff4))!=[]:
			m2=list(set(ff).intersection(ff2).intersection(ff3).intersection(ff4))
			prior2=[]
			for i in m2:
				dec=int(i[1:])
				prior2.append(dec)
			rul2=str("r"+str(min(prior2)))
			action=self.classify[rul2][ACTION]
			self.logger.info(" --- Packet matched rule-------- %s. Action is %s" % (rul2, self.classify[rul2][ACTION]))

		elif list(set(ff).intersection(ff2).intersection(ff3))!=[]:
			m3=list(set(ff).intersection(ff2).intersection(ff3))
			prior3=[]
			for i in m3:
				dec=int(i[1:])
				prior3.append(dec)
			rul3=str("r"+str(min(prior3)))
			action=self.classify[rul3][ACTION]
			self.logger.info(" --- Packet matched rule-------- %s. Action is %s" % (rul3, self.classify[rul3][ACTION]))

		elif  list(set(ff).intersection(ff2))!=[]:
			m4=list(set(ff).intersection(ff2))
			prior4=[]
			for i in m4:
				dec=int(i[1:])
				prior4.append(dec)
			rul4=str("r"+str(min(prior4)))
			action=self.classify[rul4][ACTION]
			self.logger.info(" --- Packet matched rule-------- %s. Action is %s" % (rul4, self.classify[rul4][ACTION])) 
		# here if will found nothing commin among best prefixes we will search from otther prefixes, bcz also in other prefixes we could fine best rules ,it is neccessary bcz also in theory part we search
		elif list(set(f1_all).intersection(f2_all).intersection(f3_all).intersection(f4_all).intersection(f5_all))!=[]:
				
			m1=list(set(f1_all).intersection(f2_all).intersection(f3_all).intersection(f4_all).intersection(f5_all))
			prior1=[]
			for i in m1:
				dec=int(i[1:])
				prior1.append(dec)

			rul=str("r"+str(min(prior1)))
			action=self.classify[rul][ACTION]
			self.logger.info(" ---- Packet matched rule from other prefixes-------- %s. Action is %s" % (rul, self.classify[rul][ACTION]))  
		
		elif list(set(f1_all).intersection(f2_all).intersection(f3_all).intersection(f4_all))!=[]:
			m2=list(set(f1_all).intersection(f2_all).intersection(f3_all).intersection(f4_all))
			prior2=[]
			for i in m2:
				dec=int(i[1:])
				prior2.append(dec)
			rul2=str("r"+str(min(prior2)))
			action=self.classify[rul2][ACTION]
			self.logger.info(" --- Packet matched rule- from other prefixes------- %s. Action is %s" % (rul2, self.classify[rul2][ACTION]))

		elif list(set(f1_all).intersection(f2_all).intersection(f3_all))!=[]:
			m3=list(set(f1_all).intersection(f2_all).intersection(f3_all))
			prior3=[]
			for i in m3:
				dec=int(i[1:])
				prior3.append(dec)
			rul3=str("r"+str(min(prior3)))
			action=self.classify[rul3][ACTION]
			self.logger.info(" --- Packet matched rule- from other prefixes-------- %s. Action is %s" % (rul3, self.classify[rul3][ACTION]))

		elif  list(set(f1_all).intersection(f2_all))!=[]:
			m4=list(set(f1_all).intersection(f2_all))
			prior4=[]
			for i in m4:
				dec=int(i[1:])
				prior4.append(dec)
			rul4=str("r"+str(min(prior4)))
			action=self.classify[rul4][ACTION]
			self.logger.info(" --- Packet matched rule-from other prefixes------- %s. Action is %s" % (rul4, self.classify[rul4][ACTION])) 
		
		

			#if we found nothing commong rules among best prefixes and others prefixes we will assign rule based on fisrt field ,and find best prefix
		else:
		
			prior5=[]
			for i in ff:
				dec=int(i[1:])
				prior5.append(dec)
			

			rul5=str("r"+str(min(prior5)))
			action=self.classify[rul5][ACTION]

			self.logger.info(" --- Packet matched rule-------- %s. Action is %s" % (rul5, self.classify[rul5][ACTION])) 
		


		return action
		
	



	def linear_classification(self, src_ip, dst_ip, proto, sport, dport):
		action = "deny"
		self.logger.info(" --- Packet classification") 

		# check matching rule
		for rule in sorted(self.classify):
			match = self.classify[rule]
			if (match[SRC_IP] == src_ip or match[SRC_IP] == "*") and \
				(match[DST_IP] == dst_ip or match[DST_IP] == "*") and \
				(match[PROTO]  == proto  or match[PROTO]  == "*") and \
				(match[SPORT]  == sport  or match[SPORT]  == "*") and \
				(match[DPORT]  == dport  or match[DPORT]  == "*") :
				self.logger.info(" --- Packet matched rule %s. Action is %s" % (rule, match[ACTION]))
				action = match[ACTION]
				self.counters[rule] = self.counters[rule] + 1
				return action
		
		return action







#here we create common function in order to implement the project
class Node():
	

	#initialization of a node for the tree
	def __init__(self,key):
		self.key = key
		self.left = None
		self.right = None
		self.parent = None
		self.rule = []


		
	#adding a rule address to the tree
	def add_rule(self, rule):
		
		
		#self.rule=rule
		self.rule.append(rule)
	
#class Tree for creation the treee  
class Tree():

       	
        #initialization of the tree setting the root to None
        def __init__(self):
		self.root = None

		
	#building the tree appending one node
	def add_node(self,key,node=None):
                global length
                #setting the root
		if node is None:
			node = self.root
		
		if self.root is None:
			self.root = Node(key)
		else: 
                        if (key[length]=='0'):
                                length=length+1 
				#adding left node      
				if node.left is None:
					node.left = Node(key)
					node.left.parent = node
                                        length=0
					return 
				else:
					#adding nodes to the left one
					return self.add_node(key,node = node.left)
			else:
                                length=length+1
				#adding right node
				if node.right is None:
					node.right = Node(key)
					node.right.parent = node
                                        length=0
					return 
				else:
					#adding nodes to the right one 
					return self.add_node(key,node = node.right)
	

	

############################################################################################################################
	#searching a specific node to assign him a rulle		
	def add_rule(self,key, l, rule, node):
		
		if node is None:
			node = self.root


		if self.root.key == key:
			print "key is at the root::", node.key
			node.add_rule(rule)
			print "rule is ::",rule
			return self.root
		else:
			#### Never put rule a*, 0, 1 ####
			
			if len(node.key) == len(key):

				#print "\nact", rule
				#rule=rule+rule
				#print "added to node: ", node.key
				

				
				node.add_rule(rule)
				#print "s", node.add_rule(rule)
			
				l = 0
				return 
			elif key[l] == "0" and node.left is not None:
				l = l + 1
				#print "s", key
				return self.add_rule(key, l, rule, node = node.left)
			
			elif key[l] == "1" and node.right is not None:
				l = l + 1
				return self.add_rule(key, l, rule, node = node.right)
			else:
				l = 0;
				return None
	###################################################################################################################
	#print of the tree with nodes ordered by level	
	def print_tree(self, head, queue=deque()):
		if head is None:
       			return
    		print "\nkey: ", head.key, "\nrule: ", head.rule
    		
		if head.right is not None:
			print "Node right: ", head.right.key
		else:	print "Node right:  --"
		if head.left is not None:
			print "Node left: ", head.left.key
		else:	print "Node left:  --"
    		[queue.append(node) for node in [head.left, head.right] if node]
    		if queue:
        		self.print_tree(queue.popleft(), queue)

	


	def finding_prefix_src(self, IP_add_str, n1, i):
		
		
		global last_prefix
			
		IP_add_bin = fromIPtoBinary(IP_add_str);
		#here i put additional zeros bcz, while searching prefix , we will not hold last rule in the Tree, it doesnt impact to correctness of script
		IP_add_bin+="00"		
		
		
		source_all.append(n1.rule)
		
		if last_prefix == '*':
			
			return "*";
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			#sort.append(n1.rule)
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				
				i = i +1;

				if n1.rule is not None:
					
					last_prefix= n1.rule;
					
					
				return self.finding_prefix_src(IP_add_str, n1.left, i);

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				

				if n1.rule is not None:
					last_prefix = n1.rule;

						
				return self.finding_prefix_src(IP_add_str, n1.right, i);
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					return n1.rule;
					#print "=========smotri",data
				else:
					
					return last_prefix;
		else:
			
			return last_prefix;
#func finding prefix for destination ip 
	def finding_prefix_dst(self, IP_add_str, n1, i):
		
		
		
		global last_prefix
			
		IP_add_bin = fromIPtoBinary(IP_add_str);
		#IP_add_bin = IP_add_str;
		IP_add_bin+="00"		
		#sort=[]

		##############################
		#sort=[]
		#buk=[]
		
		dst_all.append(n1.rule)
		
		if last_prefix == '*':
			
			return "*";
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			#sort.append(n1.rule)
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				
				i = i +1;

				if n1.rule is not None:
					
					last_prefix= n1.rule;
					
					
				return self.finding_prefix_dst(IP_add_str, n1.left, i);

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				

				if n1.rule is not None:
					last_prefix = n1.rule;

						
				return self.finding_prefix_dst(IP_add_str, n1.right, i);
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					return n1.rule;
					#print "=========smotri",data
				else:
					
					return last_prefix;
		else:
			
			return last_prefix;




#func finding prefix for destination ip 
	def finding_prefix_one(self, IP_add_str, n1, i):
		#global buk
		
		
		global last_prefix
		if IP_add_str=="*":
			print "root"
			print "Nothing"
		
		IP_add_bin = IP_add_str;
		IP_add_bin+="1"		
		
		sort.append(last_prefix)
		
		
		if last_prefix == '*':
			
			return "*";
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			#sort.append(n1.rule)
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				
				i = i +1;

				if n1.rule is not None:
					
					last_prefix= n1.rule;
					
					
				return self.finding_prefix_one(IP_add_str, n1.left, i);

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				

				if n1.rule is not None:
					last_prefix = n1.rule;

						
				return self.finding_prefix_one(IP_add_str, n1.right, i);
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					return n1.rule;
					#print "=========smotri",data
				else:
					
					return last_prefix;
		else:
			
			return last_prefix;

		



	def finding_prefix_sport(self, IP_add_str, n1, i):
		
		
		global last_prefix
		if IP_add_str=="*":
			print "root"
			print "Nothing"
		
		IP_add_bin = IP_add_str;
		IP_add_bin+="1"		
		
		sport_all.append(last_prefix)
		#buk=[]
		#buk.append(n1.rule)
		
		if last_prefix == '*':
			
			return "*";
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			#sort.append(n1.rule)
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				
				i = i +1;

				if n1.rule is not None:
					
					last_prefix= n1.rule;
					
					
				return self.finding_prefix_sport(IP_add_str, n1.left, i);

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				

				if n1.rule is not None:
					last_prefix = n1.rule;

						
				return self.finding_prefix_sport(IP_add_str, n1.right, i);
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					return n1.rule;
					#print "=========smotri",data
				else:
					
					return last_prefix;
		else:
			
			return last_prefix;


	def finding_prefix_dport(self, IP_add_str, n1, i):
		#global buk
		
		
		global last_prefix
		if IP_add_str=="*":
			print "root"
			print "Nothing"
		#IP_add_bin = fromIPtoBinary(IP_add_str);
		IP_add_bin = IP_add_str;
		IP_add_bin+="1"		
		#sort=[]
		#print "lllllllllllllll", last_prefix
		##############################
		dport_all.append(last_prefix)
		#buk=[]
		#buk.append(n1.rule)
		
		if last_prefix == '*':
			
			return "*";
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			#sort.append(n1.rule)
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				
				i = i +1;

				if n1.rule is not None:
					
					last_prefix= n1.rule;
					
					
				return self.finding_prefix_dport(IP_add_str, n1.left, i);

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				

				if n1.rule is not None:
					last_prefix = n1.rule;

						
				return self.finding_prefix_dport(IP_add_str, n1.right, i);
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					return n1.rule;
					#print "=========smotri",data
				else:
					
					return last_prefix;
		else:
			
			return last_prefix;







		
#here we put additional script which is out of Class node , bcz we dont need to relate it inside the class

#here we convert to binary version for add_rule function using
def fromIPtoBinary_rule(string):
	out=""
	w=string.split(".")
	
	for i in w:
		k= bin(int(i))[2:]
		
		padded=k.zfill(8)
		
		out=out+padded
		
		
	
	
	return out



#function to convert into binary
def fromIPtoBinary_1(string):
	out=""
	binaryN=[]
	
		
	w=string.split(".")
	
	for i in w:
		k= bin(int(i))[2:]
		
		padded=k.zfill(8)
		out=out+padded
		binaryN.append(padded)
	Binary=out.ljust(32,'0')	
		
		
		
	
		
		
	return Binary
#convert port address into binary version
def fromIPtoBinary_port(string):

	if string!="*":
		k= bin(int(string))[2:]
	else:
		k=""
	
		
		
		
	
		
		
	return str(k)


def fromBinarytoIP(string):
	splitter = 8
	divided = [string[i:i+splitter] for i in range(0, len(string), splitter)]
	decimal = []
	i = 0
	while i < 4:
		decimal.append(int(divided[i], 2))
		i = i + 1
	IPaddress = str(decimal[0])
	for i in range(1,4):
		IPaddress = IPaddress +'.'+ str(decimal[i])
	return str(IPaddress)


def fromIPtoBinary(string):
	if string=="*":
		print "hello"
		return
	else:
	
		w1, w2, w3, w4 = string.split(".")
		binaryN = [ str(bin(int(w1)))[2:], str(bin(int(w2)))[2:], str(bin(int(w3)))[2:], str(bin(int(w4)))[2:]]
		binaryN = paddingAddress(binaryN)
		addressIP = binaryN[0]
		i=1
		while i<4:
			addressIP = addressIP+binaryN[i]
			i=i+1
		return str(addressIP)


def paddingAddress(list):
	i = 0
	padded_list = list;
	while i < len(list):
		if len(list)<8:
			while len(padded_list[i]) < 8:
				padded_list[i] = '0' + padded_list[i]
		i = i + 1
	return padded_list








length=0
last_prefix=None 

#here we create global vectors in order to save all rules while searching best prefix

global source_all
source_all=[]
global dst_all
dst_all=[]
global sport_all
sport_all=[]

global dport_all
dport_all=[]

global sort
sort=[]








	
app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')		