#!/usr/bin/python
from collections import deque



def fromIPtoBinary(string):
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


class Node():

	#initialization of a node for the tree
	def __init__(self,key):
		self.key = key
		self.left = None
		self.right = None
		self.parent = None
		self.gateway = None
	
	#adding a gateway address to the tree
	def add_action(self, gateway):
		self.gateway = gateway;
	
  
class Tree():
        
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
		
	def add_action(self,key, l, gateway, node):
		if node is None:
			node = self.root

		if self.root.key == key:
			print "key is at the root"
			return self.root
		else:
			
			if len(node.key) == len(key):
				print "Action added to node: ", node.key
				node.add_action(gateway)
				l = 0
				return 
			elif key[l] == "0" and node.left is not None:
				l = l + 1
				return self.add_action(key, l, gateway, node = node.left)
			
			elif key[l] == "1" and node.right is not None:
				l = l + 1
				return self.add_action(key, l, gateway, node = node.right)
			else:
				l = 0;
				return None
	
	#print of the tree with nodes ordered by level	
	def print_tree(self, head, queue=deque()):
		if head is None:
       			return
    		print "\nkey: ", head.key, "\nGw: ", head.gateway
		if head.right is not None:
			print "Node dx: ", head.right.key
		else:	print "Node dx:  --"
		if head.left is not None:
			print "Node sx: ", head.left.key
		else:	print "Node sx:  --"
    		[queue.append(node) for node in [head.left, head.right] if node]
    		if queue:
        		self.print_tree(queue.popleft(), queue)
			
	def finding_prefix(self, IP_add_str, n1, i):
		global last_prefix
		#IP_add_bin = fromIPtoBinary(IP_add_str);
		IP_add_bin = IP_add_str;		
	
		if last_prefix == '*':
			#default address
			return "*";
		
		
		if i<len(IP_add_bin):
			
			
			if IP_add_bin[i] == "0" and n1.left is not None:
				i = i +1;
				if n1.gateway is not None:
					last_prefix = n1.gateway;
				return self.finding_prefix(IP_add_str, n1.left, i);
	
			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				if n1.gateway is not None:
					last_prefix = n1.gateway;
				return self.finding_prefix(IP_add_str, n1.right, i);
				
			else:
				if n1.gateway is not None:
					print "search finished\n"
					return n1.gateway;
				else:
					return last_prefix;
		else:
			
			print "no matchi", last_prefix
			return last_prefix;
	


		
k="192.123.34.34"			
sd=fromIPtoBinary(k)
print"/n Ip address translated to binary version",k		
print sd		
length=0
last_prefix=None 
t=Tree()
t.add_node(sd)
t.add_node("0")
t.add_node("1")
t.add_node("01")
t.add_node("00")
t.add_node("001")
t.add_node("0010")
t.add_node("0011")
t.add_node("00110")
t.add_node("001101")
t.add_node("10")
t.add_node("11")
t.add_node("100")
t.add_node("101")
t.add_node("1010")
t.add_node("1011")
t.add_node("10110")
t.add_node("101100")
t.add_node("101101")

t.add_action("101", 0, "sdsd", None);
t.add_action("01", 0, "ssss", None);
t.add_action("0010", 0, "128.3", None);
t.add_action("001101", 0, "128.1", None);
t.add_action("11000000011110110010001000100010", 0, "action drop packet", None);


x=t.finding_prefix("110000000111101100100010001",t.root,0)
print x


t.print_tree(t.root)
