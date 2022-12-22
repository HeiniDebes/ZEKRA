from poseidon.poseidon_constants import POSEIDON_C
from poseidon.poseidon_constants import POSEIDON_M

p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def exp5(in1):
	in2=in1*in1%p
	in4=in2*in2%p 
	in5=in4*in1%p
	return in5

def ark(state, C, r):
	for i in range(0, len(state)):
		state[i] = state[i] + C[i+r] % p
	return state

def mix(state, M):
	lc = 0
	output = []
	for i in range(0, len(state)):
		lc = 0
		for j in range(0, len(state)):
			lc = lc + M[i][j]*state[j] % p
		output.append(lc)
	return output

def sbox(nRoundsF, nRoundsP, state, i):
	if ((i < nRoundsF/2) or (i >= nRoundsF/2 + nRoundsP)):
		for j in range(0, len(state)):
			state[j] = exp5(state[j])
	else:
		state[0] = exp5(state[0])
	return state

def poseidon_hash(input):
	nInputs = len(input)-1
	N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63]
	t = nInputs + 1
	nRoundsF = 8
	nRoundsP = N_ROUNDS_P[t - 2]

	C = POSEIDON_C(t)
	M = POSEIDON_M(t)

	state = []
	for item in input:
		state.append(item)
	for i in range(0, nRoundsF + nRoundsP):
		state = ark(state, C, i*t)
		state = sbox(nRoundsF, nRoundsP, state, i)
		state = mix(state, M)

	for idx,scalar in enumerate(state):
		state[idx] = state[idx] % p
	return state
