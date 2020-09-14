
class Node:
	def __init__(self, num, lev, fath):
		self.number = num
		self.level = lev
		self.father = fath
		self.rules = {}
		self.matchedRule = "matchedRule"
		#self.children = {}


def generation_tree(self):

	# generation of the node0, the root of the tree, which contains all the rules
	root = Node(0,0,None)
	for rule in sorted(self.classify):
		root.rules.append(rule)
	root.matchedRule = " "
	tree = {0:root}

	for l in range(1,6)
		for n in tree.values()
			i = 0
			if n.level == l-1
				for ru in sorted(n.rules)
					count = 0			#se nessun nodo ha già quella regola in matchedRule, creo il nodo con quella regola
					for o in tree.values()
						if o.level == l
							if o.matchedRule == ru[l]
								count = count + 1
					if count == 0
						key = l*100+i
						tree[key] = Node(i,l,n)
						tree[key].matchedRule = ru[l]
						for r in sorted(tree[key].father.rules)
							if r[l] == tree[key].matchedRule
								tree[key].rules.append(r)
						i = i+1

	return tree

