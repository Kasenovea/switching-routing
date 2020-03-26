
from collections import deque


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







#####################################################################################################################


class Node():

	#initialization of a node for the tree
	def __init__(self,key):
		self.key = key
		self.left = None
		self.right = None
		self.parent = None
		self.rule = None
		
	#adding a rule address to the tree
	def add_rule(self, rule):
		self.rule = rule;
	
  
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
			print "key is at the root"
			return self.root
		else:
			#### Never put rule a*, 0, 1 ####
			
			if len(node.key) == len(key):
				#print "\nact", rule
				#print "added to node: ", node.key
				node.add_rule(rule)
				l = 0
				return 
			elif key[l] == "0" and node.left is not None:
				l = l + 1
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
			
	
###########################################################################################################################


	def finding_prefix(self, IP_add_str, n1, i):
		global last_prefix
		global data
		IP_add_bin = fromIPtoBinary(IP_add_str);
		#IP_add_bin = IP_add_str;		
		
		##############################
		

		data=[]
		data.append(n1.rule)

		#data.append(last_prefix)


		#print "ddd", data
			###################################################

		if last_prefix == '*':
			#default address
			return "*";
			
		# search index < of binary address length
		if i<len(IP_add_bin):
			
			data.append(last_prefix)
			#print "banch of rules at each level", data
			# next character of the IP is a zero and current node has a child
			if IP_add_bin[i] == "0" and n1.left is not None:
				i = i +1;

				if n1.rule is not None:
					data.append(last_prefix)
					last_prefix= n1.rule;
					#print "sss", last_prefix
				return self.finding_prefix(IP_add_str, n1.left, i);

			# next character of the IP is a one and current node has a child

			elif IP_add_bin[i] == "1" and n1.right is not None:
				i = i +1;
				

				if n1.rule is not None:
					last_prefix = n1.rule;
					#print "ddd", last_prefix	
				return self.finding_prefix(IP_add_str, n1.right, i);
			

			# if I get here, I don't have kids, I'm at the bottom of the tree
			else:

				if n1.rule is not None:
					
					print "searching stopped we are at rule"
					return n1.rule;

				else:
					return last_prefix;
		else:
			

			## no final matching, return to saved prefix
			print "\nSearching stopped: we found nothing, last prefix is : ", last_prefix
			return last_prefix;
			
###############################################################################################################

length=0
last_prefix=None 
f1=Tree()
f1.add_node("*")
f1.add_node("0")
f1.add_node("1")
f1.add_node("00")
f1.add_node("000")
f1.add_node("0000")
f1.add_node("001")
f1.add_node("0010")
f1.add_node("01")
f1.add_node("011")
f1.add_node("0110")
f1.add_node("11")
f1.add_node("111")
f1.add_node("1111")
f1.add_node("1110")
f1.add_node("110")
f1.add_node("1100")
f1.add_node("10")
f1.add_node("101")
f1.add_node("1010")




#t.add_node("0010")
#t.add_node("0011")
#t.add_node("00110")
#t.add_node("001101")
#t.add_node("10")
#t.add_node("11")
#t.add_node("100")
#t.add_node("101")
#t.add_node("1010")
#t.add_node("1011")
#t.add_node("10110")
#t.add_node("101100")
#t.add_node("101101")


f1.add_rule("0000", 0, "rule1", None);
f1.add_rule("0010", 0, "rule2", None);
f1.add_rule("0110",0,"rule3",None);
f1.add_rule("011",0,"rule4",None);
f1.add_rule("1010",0,"rule5",None);
f1.add_rule("1100",0,"rule6",None);
f1.add_rule("1110",0,"rule7",None);
f1.add_rule("1111",0,"rule8",None);


#f1.add_rule("0010", 0, "128.30.30.30", None);
#f1.add_rule("001101", 0, "128.15.0.0", None);
#f1.add_rule("10110", 0, "64.128.0.0", None);
t=fromIPtoBinary('121.222.111.22')
print t

x1=f1.finding_prefix('121.222.111.22',f1.root,0)
print "prefix in f1",x1

f1=data
print "all rules in f1", data

f2=Tree()
f2.add_node("*")
#f2.add_node_F2("0")
f2.add_node("1")
#f2.add_node_F2("00")
f2.add_node("0")
f2.add_node("00")
f2.add_node("000")
f2.add_node("0000")
f2.add_node("0001")
f2.add_node("01")
f2.add_node("010")
f2.add_node("0100")
f2.add_node("0101")
f2.add_node("011")
f2.add_node("0110")
f2.add_node("11")
f2.add_node("111")
f2.add_node("1111")
f2.add_node("10")
f2.add_node("100")
f2.add_node("1000")
f2.add_node("1001")






#adding rule 

f2.add_rule("1001",0,"rule1",None)
f2.add_rule("1000",0,"rule2",None)
f2.add_rule("0101",0,"rule3",None)
f2.add_rule("0110",0,"rule4",None)
f2.add_rule("0100",0,"rule5",None)
f2.add_rule("0001",0,"rule6",None)
f2.add_rule("0100",0,"rule7",None)
f2.add_rule("1111",0,"rule8",None)



t2=fromIPtoBinary('232.111.22.11')
print t2
x2=f2.finding_prefix('232.111.22.11',f2.root,0)


print "\nprefix in f2",x2
f2=data
print "all rules in f2", data




f3=Tree()
f3.add_node("*")
f3.add_node("0")
f3.add_node("1")
f3.add_node("00")
f3.add_node("01")
f3.add_node("10")
f3.add_node("11")
f3.add_node("000")
f3.add_node("001")
f3.add_node("010")
f3.add_node("011")
f3.add_node("111")
f3.add_node("101")


f3.add_rule("010",0,"rule1",None)
f3.add_rule("111",0,"rule2",None)

f3.add_rule("000",0,"rule3",None)
f3.add_rule("01",0,"rule4",None)
f3.add_rule("011",0,"rule5",None)
f3.add_rule("001",0,"rule1",None)
f3.add_rule("101",0,"rule1",None)
f3.add_rule("11",0,"rule1",None)






t3=fromIPtoBinary('110.220.22.3')
print t3
x3=f3.finding_prefix('110.220.22.3',f3.root,0)
print "\nprefix in f3",x3
f3=data
print "all rules in f3", data
junk=f1+f2+f3
print "junk", junk


if x1==x2:
	if x2==x3:
		rule=x3
		print "stop at f3",rule
	else:
		rule=x2
		print "stop at f2",rule

else:
	rule=x1
	print "stop at f1",rule


#f4.print_tree(f4.root)