import dimod
from dwave.system import LeapHybridSampler
from dwave.samplers import SimulatedAnnealingSampler
from typing import cast

cves = [
    {"id": "CVE-1", "severity": 9.8, "importance": 5, "time": 60},
    {"id": "CVE-2", "severity": 7.5, "importance": 3, "time": 45},
    {"id": "CVE-3", "severity": 5.0, "importance": 1, "time": 30}
]

T_max = 90
alpha = 1
beta = 1
P = 0.01

for cve in cves:
    cve['benefit'] = alpha * cve['severity'] + beta * cve['importance']

Q = {}

for i, cve in enumerate(cves):
    b_i = cve['benefit']
    t_i = cve['time']
    Q[(i, i)] = -b_i + P * (t_i**2 - 2*T_max*t_i)

for i in range(len(cves)):
    for j in range(i+1, len(cves)):
        Q[(i, j)] = P * 2 * cves[i]['time'] * cves[j]['time']

bqm = dimod.BinaryQuadraticModel.from_qubo(Q)

#sampler = LeapHybridSampler()
#result = sampler.sample(bqm, time_limit=5)

sampler = SimulatedAnnealingSampler()
result = sampler.sample(bqm, num_reads=100)

best = result.first.sample      # type: ignore
energy = result.first.energy    # type: ignore

for i, cve in enumerate(cves):
    print(f"{cve['id']}: {best[i]}")

print(f"Energy: {energy}")
