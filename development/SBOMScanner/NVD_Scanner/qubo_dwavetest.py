from dwave.system import DWaveSampler, EmbeddingComposite
import dimod

bqm = dimod.BinaryQuadraticModel({'x': -1.0}, {}, 0.0, dimod.BINARY)

sampler = EmbeddingComposite(DWaveSampler())  # uses your token
sampleset = sampler.sample(bqm, num_reads=100)
print(sampleset.first)
