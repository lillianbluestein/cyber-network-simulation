import network_generation as net_gen
import networkx as nx
import random
import copy

def generate_simulation_graphs(graph_size):
    """
    Creates 1000 undirected mesh networks of a certain size

    Parameters:
        graph_size: (int) number of nodes in each graph
    
    Returns:
        graphs: (list) contains 1000 graphs of size graph_size 
    """
    graphs = []
    for _ in range(1000): # 1000 graphs generated for Monte Carlo 
        graph = net_gen.generate_graph(graph_size)
        net_gen.assign_centralities(graph, nx.degree_centrality)
        graphs.append(graph)
    return graphs

def generate_initial_networks(graphs, defense_budget, attack_budget):
    """
    Creates initial cyber networks for Monte Carlo simulation

    Parameters:
        graphs: (list) contains 1000 undirected mesh networks of a certain size
        defense_budget: (int) overall defense budget allocation 
        attack_budget: (int) overall attack budget allocation 
    
    Returns:
        networks: (list) contains 1000 graphs with initial defense and attack units
            allocated across nodes
    """
    networks = []
    for graph in graphs: 
        sorted_nodes = net_gen.sort_by_centrality(graph) # list of nodes in order of decreasing centrality
        net_gen.assign_defense_values(sorted_nodes, defense_budget)
        net_gen.assign_attack_values(sorted_nodes, attack_budget)
        networks.append(graph)
    return networks

def check_trial_conditions(graph, attack_budget):
    """
    Determines whether the current trial in the Monte Carlo simulation
    should continue. 

    This function checks if the following conditions are met:
        1. There are nodes in the network that have not been compromised.
        2. The attacker has budget remaining. 
    If either condition is False, the trial should terminate. 

    Parameters:
        graph: (NetworkX graph) represents a cyber network
        attack_budget: (int) overall attack budget allocation 
    
    Returns:
        True or False (boolean) 
    """
    network_not_compromised = all(nx.get_node_attributes(graph, 'is_compromised').values())
    has_attack_budget = attack_budget > 0
    return has_attack_budget and network_not_compromised

def deg_deg_initial_attack(graph, attack_budget):
    """
    Performs initial attack on inputted cyber network graph, in which both the attack and defense
        strategies are informed by degree centrality.
    Modifies nodes in the inputted graph by changing their attack values. 

    The initially targeted nodes have the highest centrality values. Attacks on these initially 
    targeted nodes are called "direct attacks." 
    Probability that a direct attack will result in a compromised node: 
    - 70% if the node has 1 defense unit allocated
    - 90% if the node has 0 defense units allocated (due to inherent defense in every node).

    Parameters:
        graph: (NetworkX graph) represents a cyber network
        attack_budget: (int) overall attack budget allocation
    
    Returns:
        sorted_attacked_nodes: (list) initial attack targets in order of decreasing centrality  
        attack_budget: (int) remaining attacker budget after initial attack
    """
    attack_budget -= net_gen.calc_direct_attack_budget(attack_budget)
    attacked_nodes = [node for node in graph.nodes if node.is_attacked]
    sorted_attacked_nodes = sorted(attacked_nodes, key=lambda node: node.centrality_value, reverse=True)
    for node in attacked_nodes:
        # Direct attack logic 
        if node.defense_value == 1:
            node.is_compromised = random.random() < 0.7
        else:
            node.is_compromised = random.random() < 0.9 # inherent defense in every node 
    return sorted_attacked_nodes, attack_budget


def deg_deg_trial(graph, attack_budget):
    """
    Performs a single trial in a Monte Carlo simulation of a cyber attack on a network, in 
    which both the attack and defense strategies are informed by degree centrality. 

    This function models the outcome of the attack, based on the attack and defense budgets. 
    It assesses the state of the cyber network post-attack by determining how many nodes are 
    successfully compromised by ther attacker. 

    The initially targeted nodes have the highest centrality values. Attacks on these initially 
    targeted nodes are called "direct attacks." See :func:`do_initial_attack` for direct attack logic.

    Once an initial target node has been successfully compromised, the attacker continues to attack
    adjacent nodes in the network. These adjacent attacks are called "indirect attacks."
    The current compromised node is called "current_node," and the adjacent node to be attacked is 
    called "target_node."
    Probabilities that indirect attacks will result in target_node being compromised: 
    - 50% if current_node has 0 defense units allocated & target_node has 1.
    - 75% if current_node has 1 defense unit allocated & target_node has 0. 
    - 25% if both have 1 defense unit allocated.
    - 90% if both have 0 defense units allocated (due to inherent defense in every node).
    Compromised nodes are queued for indirect attacks on adjacent nodes.
        
    Parameters:
        graph: (NetworkX graph) represents a cyber network
        attack_budget: (int) overall attack budget allocation 
    
    Returns:
        frac_compromised: (float) fraction of nodes in the network successfully compromised by the attacker 
    """
    targets, attack_budget = deg_deg_initial_attack(graph, attack_budget) # targets: queue of nodes to be attacked
    while check_trial_conditions(graph, attack_budget) and len(targets) > 0: 
        current_node = targets.pop()
        if current_node.is_compromised:
            connected_nodes = list(graph.neighbors(current_node))
            next_targets = sorted(connected_nodes, key=lambda node: node.centrality_value, reverse=True)
            for target in next_targets:
                if check_trial_conditions(graph, attack_budget) and not target.is_attacked:
                    target.is_attacked = True
                    targets.append(target) 
                    attack_budget -= 0.5 
                    # Indirect attack logic 
                    if target.defense_value == 1 and current_node.defense_value == 0:
                        target.is_compromised = random.random() < 0.5
                    elif target.defense_value == 0 and current_node.defense_value == 1:
                        target.is_compromised = random.random() < 0.75
                    elif target.defense_value == 1 and current_node.defense_value == 1:
                        target.is_compromised = random.random() < 0.25
                    elif target.defense_value == 0 and current_node.defense_value == 0:
                        target.is_compromised = random.random() < 0.9 # inherent defense in every node 
    num_compromised = sum(1 for node in graph.nodes if node.is_compromised)
    frac_compromised = num_compromised/(graph.number_of_nodes())
    return frac_compromised

def monte_carlo(graphs, strategy_mapping_func, attack_budget):
    """
    Performs Monte Carlo simulation of a cyber attack on a network.
    Each trial models the outcome of the attack based on the specific defense and attack budgets. 
    
    Parameters:
        graph: (NetworkX graph) represents a cyber network
        strategy_mapping_func: (func) performs a single cyber attack trial with specific attack and
            defense strategies 
        attack_budget: (int) overall attack budget allocation
    
    Returns:
        infiltration_data: (list) contains the number of compromised nodes in each trial of the simulation  
    """
    infiltration_data = []
    for graph in graphs:
        frac_compromised = strategy_mapping_func(graph, attack_budget)
        infiltration_data.append(frac_compromised)
    return infiltration_data

def generate_standard_networks():
    """
    Creates 1000 undirected mesh networks of the following sizes:
        - n = 50
        - n = 100
        - n = 250
        - n = 500
    These graphs are used in Monte Carlo simulations across different budget and strategy mappings.
    The structure of these graphs remains constant throughout the experiments to ensure consistency
    and isolate the effects of varying budgets and strategies.

    Parameters:
        None
    
    Returns:
        size50, size100, size250, size500: (tuple) a collection of lists, each containing 1000 graphs
            for each size n 
    """
    size50 = generate_simulation_graphs(50)
    size100 = generate_simulation_graphs(100)
    size250 = generate_simulation_graphs(250)
    size500 = generate_simulation_graphs(500)
    return size50, size100, size250, size500

def generate_data(standard_networks, strategy_mapping_func):
    """
    Generates infiltration data for a given attack/defense strategy across different graph 
        sizes and budget mappings

    Parameters:
        standard_networks: (tuple) a collection of lists, each containing 1000 graphs of different 
            sizes. These graphs form the base for creating the initial cyber networks in the simulation.
        strategy_mapping_func: (func) performs a single cyber attack trial with specific attack and 
            defense strategies 
    
    Returns:
        graph_dicts: (list) a collection of dictionaries, each containing infiltration data for 
            various budget mappings across different graph sizes
    """
    size50, size100,size250, size500 = {}, {}, {}, {}
    graph_dicts = [size50, size100, size250, size500]
    # (defense budget, attack budget)
    budget_mappings = [(60, 60), (60, 100), (45, 100), (25, 100), (60, 75), (25, 75), (35, 75), (60, 50)]
    for standard_networks_n, graph_dict in zip(standard_networks, graph_dicts):
        for budget_mapping in budget_mappings:
            defense_budget, attack_budget = budget_mapping
            graphs = generate_initial_networks(copy.deepcopy(standard_networks_n), defense_budget, attack_budget)
            infiltration_data = monte_carlo(graphs, strategy_mapping_func, attack_budget)
            graph_dict[budget_mapping] = infiltration_data
    return graph_dicts


