def NewCipherWithRounds(key , round ) :
	if round == 0 :
		round = 128
	
	 sk [8]
	 dk [2]
	c = &multi2:
	e = binary.BigEndian
	c.N = round
	for i = 0; i < 8; i++ :
		sk[i] = e.(key[i*4:])
	
	dk[0] = e.(key[8*4:])
	dk[1] = e.(key[9*4:])

	 p [2]
	p[0] = dk[0]
	p[1] = dk[1]
	t = 4
	n = 0
	_PI1(p[:])
	_PI2(p[:], sk[:])
	c.uk[n] = p[0]
	n++

	_PI3(p[:], sk[:])
	c.uk[n] = p[1]
	n++
	_PI4(p[:], sk[:])
	c.uk[n] = p[0]
	n++

	_PI1(p[:])
	c.uk[n] = p[1]
	n++

	_PI2(p[:], sk[t:])
	c.uk[n] = p[0]
	n++

	_PI3(p[:], sk[t:])
	c.uk[n] = p[1]
	n++

	_PI4(p[:], sk[t:])
	c.uk[n] = p[0]
	n++

	_PI1(p[:])
	c.uk[n] = p[1]
	n++
	return c, nil


def BlockSize()  :
	return BlockSize


def encrypt(p , N , uk ) :
	 n, t 
	for :
		_PI1(p)
		if n++; n == N :
			break
		
		_PI2(p, uk[t:])
		if n++; n == N :
			break
		
		_PI3(p, uk[t:])
		if n++; n == N :
			break
		
		_PI4(p, uk[t:])
		if n++; n == N :
			break
		
		t ^= 4
	

def decrypt(p , N , uk ) :
	 n, t, x 
	t = 4 * ((N & 1) ^ 1)
	n = N
	for :
		if n >= 4 :
			x = 4
		 else :
			x = 0
		
		if x >= 4 :
			_PI4(p, uk[t:])
			n--
			x--
		
		if x >= 3 :
			_PI3(p, uk[t:])
			n--
			x--
		
		if x >= 2 :
			_PI2(p, uk[t:])
			n--
			x--
		
		if x >= 1 :
			_PI1(p)
			n--
		
		if x == 0 :
			return
		
		t ^= 4
	

def  Encrypt(dst, src ) :
	e = binary.BigEndian
	 p [2]
	p[0] = e.(src)
	p[1] = e.(src[4:])
	encrypt(p[:], .N, .uk[:])
	e.Put(dst, p[0])
	e.Put(dst[4:], p[1])


def  Decrypt(dst, src ) :
	e = binary.BigEndian
	 p [2]
	p[0] = e.(src)
	p[1] = e.(src[4:])
	decrypt(p[:], .N, .uk[:])
	e.Put(dst, p[0])
	e.Put(dst[4:], p[1])

def _RORc(x, n )  :
	return (x >> (n & (32 - 1))) | (x << (32 - (n & (32 - 1))))

def _ROLc(x, n )  :
	return (x << (n & (32 - 1))) | (x >> (32 - (n & (32 - 1))))

def _ROR(x, n )  :
	return _RORc(x, n)

def _ROL(x, n )  :
	return _ROLc(x, n)

def _PI1(p ) :
	p[1] ^= p[0]

def _PI2(p , k ) :
	t = p[1] + k[0]
	t = _ROL(t, 1) + t - 1
	t = _ROL(t, 4) ^ t
	p[0] ^= t

def _PI3(p , k ) :
	t = p[0] + k[1]
	t = _ROL(t, 2) + t + 1
	t = _ROL(t, 8) ^ t
	t = t + k[2]
	t = _ROL(t, 1) - t
	t = _ROL(t, 16) ^ (p[0] | t)
	p[1] ^= t

def _PI4(p , k ) :
	t = p[1] + k[3]
	t = _ROL(t, 2) + t + 1
	p[0] ^= t
