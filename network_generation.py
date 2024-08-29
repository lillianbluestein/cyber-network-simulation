import networkx as nx
import math

class Node:
    """
    Creates a node in cyber network
    """
    def __init__(self, name):
        self.name = name 
        self.defense_value = 0
        self.attack_value = 0 
        self.centrality_value = None
        self.is_attacked = False
        self.is_compromised = False
    
    def __str__(self):
        return f"Node Object {self.name}"
    
    def __repr__(self):
        return f"Node Object {self.name}"
   
    def set_centrality_value(self, centrality_value):
        self.centrality_value = centrality_value

def generate_graph(n, p=0.5):
    """
    Generates a connected, undirected Erdos-Renyi graph G(n, p)

    Parameters:
        n: (int) number of nodes
        p: (float) probability of edge creation between node pair

    Returns:
        graph: (NetworkX graph) an Erdos-Renyi graph G(n, p)
    """
    graph = nx.erdos_renyi_graph(n, p)
    mapping = {node: Node(node) for node in graph.nodes}
    graph = nx.relabel_nodes(graph, mapping)
    if not nx.is_connected(graph):
        return generate_graph(n, p)
    else:
        return graph
    
def assign_centralities(graph, centrality_func):
    """
    Modifies graph to add centrality values of type centrality_func to nodes 

    Parameters:
        graph: (NetworkX graph) 
        centrality_func: (func) centrality type
    
    Returns:
        None 
    """
    centralities = centrality_func(graph)
    for node in graph:
        node.set_centrality_value(centralities[node])

def sort_by_centrality(graph):
    """
    Sorts nodes in a graph in order of decreasing centrality value 

    Parameters:
        graph: (NetworkX graph) 
    
    Returns:
        sorted_nodes: (list) nodes in order of decreasing centrality value 
    """
    sorted_nodes = sorted(graph.nodes, key=lambda node: node.centrality_value, reverse=True)
    return sorted_nodes

def assign_defense_values(sorted_nodes, defense_budget):
    """
    Modifies graph to add defense values to nodes 

    Defense Value Allocation Logic: 
    - The entire defense budget is used to assign defense values to nodes.
    - The cost to defend a node is 1 unit 
    - Units are allocated to nodes with the highest centrality values

    Parameters:
        sorted_nodes: (list) nodes in order of decreasing centrality value
        defense_budget: (int) overall defense budget allocation 
    
    Returns: 
        None
    """
    if len(sorted_nodes) < defense_budget:
        defense_budget = len(sorted_nodes)
    for i in range(defense_budget):
        sorted_nodes[i].defense_value = 1

def calc_direct_attack_budget(attack_budget):
    """
    Calculates amount used to attack the initial target nodes
    This amount is 5% of the overall attack budget. 

    Parameters:
        attack_budget: (int) overall defense budget allocation 
    
    Returns:
        direct_attack_budget: (int) amount used for initial attack
    """
    direct_attack_budget = math.ceil(0.05 * attack_budget)
    return direct_attack_budget

def assign_attack_values(sorted_nodes, attack_budget):
    """
    Modifies graph to add initial attack values to nodes 

    Parameters:
        sorted_nodes: (list) nodes in order of decreasing centrality value
        attack_budget: (int) overall attack budget allocation 

    Attack Value Allocation Logic: 
    - 5% of the attack budget is used for the initial/direct attack 
    - The cost to perform a direct attack on a node is 1 unit 
    - The entire direct attack budget is used to attack the initial targets 
    
    Returns: 
        None
    """
    direct_attack_budget = calc_direct_attack_budget(attack_budget)
    for i in range(direct_attack_budget):
        sorted_nodes[i].attack_value = 1
        sorted_nodes[i].is_attacked = True

