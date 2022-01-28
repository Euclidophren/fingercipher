def E(X , L)  :
	Y = [0] * 16
	for i in range(16):
		Y[i] = X[i%L]
	return Y


def PHT(inp):
	out = [0] * 2
	out[0] = ((2*inp[0] + inp[1])%256)
	out[1] = ((inp[0] + inp[1])%256)
	return out


def e(i) :
	I  = big.NewInt(inpt64(i))
	I.Exp(big.NewInt(45), I, big.NewInt(257))
	I.Mod(I, big.NewInt(256))
	return I.Uinpt64()


def l(i) :
	j = [0] * 256
	for j in range(256):
		if e[j] == i:
			return j
	return 0

