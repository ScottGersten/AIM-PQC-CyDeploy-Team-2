import dimod
from dwave.samplers import SimulatedAnnealingSampler
import json

# Attack Vector
AV = {
    'NETWORK': 0.85,
    'ADJACENT_NETWORK': 0.62,
    'LOCAL': 0.55,
    'PHYSICAL': 0.20
}

# Attack Complexity
AC = {
    'LOW': 0.77,
    'HIGH': 0.44
}

# Privileges Required -- Scope Unchanged
PR_SU = {
    'NONE': 0.85,
    'LOW': 0.62,
    'HIGH': 0.27
}

# Privileges Required -- Scope Changed
PR_SC = {
    'NONE': 0.85,
    'LOW': 0.68,
    'HIGH': 0.50
}

# User Interaction
UI = {
    'NONE': 0.85,
    'REQUIRED': 0.62
}

# Scope
S = {
    'UNCHANGED': 1.00,
    'CHANGED': 1.08
}

# Confidentiality Impact
C = {
    'NONE': 0.00,
    'LOW': 0.22,
    'HIGH': 0.56
}

# Integrity Impact
I = {
    'NONE': 0.00,
    'LOW': 0.22,
    'HIGH': 0.56
}

# Availability Impact
A = {
    'NONE': 0.00,
    'LOW': 0.22,
    'HIGH': 0.56
}

def get_vuln_list(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        vuln_list = json.load(file)
        return vuln_list
    
def get_numerical(vuln_list):
    vuln_weights = []
    for item in vuln_list:
        if item['attack_vector'] is not None:
            vuln_weights.append({
                'id': item.get('id'),
                'desc': item.get('desc'),
                'AV': AV[item.get('attack_vector')],
                'AC': AC[item.get('attack_complexity')],
                'PR': PR_SU[item.get('privileges_required')] if item.get('scope') == 'UNCHANGED' else PR_SC[item.get('privileges_required')],
                'UI': UI[item.get('user_interaction')],
                'S': S[item.get('scope')],
                'C': C[item.get('confidentiality_impact')],
                'I': I[item.get('integrity_impact')],
                'A': A[item.get('availability_impact')]
            })

    with open(r'results/vuln_weights.json', 'w', encoding='utf-8') as file:
        json.dump(vuln_weights, file, indent=2)
    
    return vuln_weights

def compute_weight(vuln):
    return vuln['AV'] + vuln['AC'] + vuln['PR'] + vuln['UI'] + vuln['S'] + vuln['C'] + vuln['I'] + vuln['A']

def build_qubo(vuln_weights, K, penalty):
    Q = {}

    w = [compute_weight(vuln) for vuln in vuln_weights]

    for i in range(len(w)):
        Q[(i, i)] = -w[i] + penalty
        for j in range(i + 1, len(w)):
            Q[(i, j)] = 2 * penalty

    for i in range(len(w)):
        Q[(i, i)] += -2 * K * penalty

    #bqm = dimod.BinaryQuadraticModel.from_qubo(Q)

    #return bqm

    return Q

def run_qubo(Q):
    sampler = SimulatedAnnealingSampler()
    result = sampler.sample_qubo(Q, num_reads=1000)
    return result.first.sample # type: ignore

def run_prioritization():
    filename = r'results/vulnerabilities.json'
    vuln_list = get_vuln_list(filename)
    vuln_weights = get_numerical(vuln_list)
    K = 5
    penalty = 6.5
    Q = build_qubo(vuln_weights, K, penalty)
    solution = run_qubo(Q)
    count = 0
    for idx, picked in solution.items():
        if picked == 1:
            count += 1
            print(f"{vuln_weights[idx]['id']} | {vuln_weights[idx]['desc']}")
    print(f"Count: {count}")