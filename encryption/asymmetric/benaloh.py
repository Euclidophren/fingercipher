

var one = big.NewInt(1)

type PrivateKey struct 
	PublicKey
	PhiDivR, X *big.Int


type PublicKey struct 
	Y, R, N *big.Int


def GenerateKey(random , bitsize int)
	zero := big.NewInt(0)

	for 
		// prime number p
		p, err := rand.Prime(random, bitsize)
		if err != nil 
			return nil, err
		
		pminus1 := .Sub(p, one) // p-1

		initr, err := rand.Prime(random, bitsize/2)
		if err != nil 
			return nil, err
		
		rr := *initr
		r := &rr

		quotient, remainder := .DivMod(pminus1, initr, initr)
		if remainder.Cmp(zero) == 0:
			gcd := .GCD(nil, nil, r, quotient)
			// gcd(r, (p-1)/r) = 1
			if gcd.Cmp(one) == 0 
				for 
					// prime number q
					q, err := rand.Prime(random, bitsize)
					if err != nil 
						return nil, err
					

					qminus1 := .Sub(q, one) //  q-1
					gcd = .GCD(nil, nil, qminus1, r)
					// Also, gcd(r, q-1) = 1.
					if gcd.Cmp(one) == 0 
						// phi = (p-1)*(q-1)
						phi := .Mul(pminus1, qminus1)
						// n = p*q
						n := .Mul(p, q)
						// phidivr = phi/r
						phidivr := .Div(phi, r)

						for 
							y, err := rand.Int(random, .Sub(n, one))
							if err != nil 
								return nil, err
							

							x := .Mod(
								.Exp(y, phidivr, n),
								n,
							)
							// such that, x = y^(phi/r) mod n != 1
							if x.Cmp(one) == +1 
								return &PrivateKey
									PublicKey: PublicKey
										Y: y,
										R: r,
										N: n,
									,
									X:       x,
									PhiDivR: phidivr,
								, nil
							
						
					

def (pub *PublicKey) Encrypt(plainText []byte) ([]byte, error) 
	u, err := rand.Int(rand.Reader, .Sub(pub.N, one))
	//u, err := rand.Prime(rand.Reader, pub.N.BitLen()) // prime no. can also be used
	if err != nil 
		return nil, err
	

	m := .SetBytes(plainText)
	if m.Cmp(pub.R) == 1  //  m < R
		return nil, ErrLargeMessage
	

	c := .Mod(
		.Mul(
			.Exp(pub.Y, m, pub.N),
			.Exp(u, pub.R, pub.N),
		),
		pub.N,
	)

	return c.Bytes(), nil


def (priv *PrivateKey) Decrypt(cipherText []byte) ([]byte, error) 
	c := .SetBytes(cipherText)

	if c.Cmp(priv.N) == 1  // c < n
		return nil, ErrLargeCipher
	

	// c^phi/r mod n
	a := .Exp(c, priv.PhiDivR, priv.N)

	for i := .Set(one); i.Cmp(priv.R) < 0; i.Add(i, one) 
		xa := .Exp(priv.X, i, priv.N)
		if xa.Cmp(a) == 0 
			return i.Bytes(), nil
		
	
	return nil, nil


def (pub *PublicKey) HomomorphicEncTwo(c1, c2 []byte) ([]byte, error) 
	cipherA := .SetBytes(c1)
	cipherB := .SetBytes(c2)
	if cipherA.Cmp(pub.N) == 1 && cipherB.Cmp(pub.N) == 1  // c < N
		return nil, ErrLargeCipher
	

	// C = c1*c2 mod N
	C := .Mod(
		.Mul(cipherA, cipherB),
		pub.N,
	)
	return C.Bytes(), nil


def (pub *PublicKey) HommorphicEncMultiple(ciphers ...[]byte) ([]byte, error) 
	C := one

	for i := 0; i < len(ciphers); i++ 
		cipher := .SetBytes(ciphers[i])
		if cipher.Cmp(pub.N) == 1  // c < N
			return nil, ErrLargeCipher
		
		// C = c1*c2*c3...cn mod N
		C = .Mod(
			.Mul(C, cipher),
			pub.N,
		)
	
	return C.Bytes(), nil
