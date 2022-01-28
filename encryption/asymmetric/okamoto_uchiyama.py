
type PrivateKey struct {
	PublicKey
	GD       *big.Int
	P        *big.Int
	PSquared *big.Int



type PublicKey struct {
	N *big.Int
	G *big.Int
	H *big.Int



func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// prime number p
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	

	// prime number q
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	


	psquare := new(big.Int).Mul(p, p)
	// n = psquare * q
	n := new(big.Int).Mul(psquare, q)


	var g, gpminuse1 *big.Int
	for {
		pminuse1 := new(big.Int).Sub(p, one)
		g, err = rand.Int(rand.Reader, new(big.Int).Sub(n, one))
		if err != nil {
			return nil, err
		

		gpminuse1 = new(big.Int).Mod(
			new(big.Int).Exp(g, pminuse1, psquare),
			psquare,
		)

		if gpminuse1.Cmp(one) != 0 {
			break
		
	

	h := new(big.Int).Mod(
		new(big.Int).Exp(g, n, n),
		n,
	)
	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
			G: g,
			H: h,
		,
		GD:       gpminuse1,
		P:        p,
		PSquared: psquare,
	, nil


func (pub *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	// choose a random integer r from {1...n-1
	r, err := rand.Int(rand.Reader, new(big.Int).Sub(pub.N, one))
	if err != nil {
		return nil, err
	

	m := new(big.Int).SetBytes(plainText)
	if m.Cmp(pub.N) == 1 { //  m < N
		return nil, ErrLargeMessage
	

	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pub.G, m, pub.N),
			new(big.Int).Exp(pub.H, r, pub.N),
		),
		pub.N,
	)
	return c.Bytes(), nil


func (priv *PrivateKey) Decrypt(cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if c.Cmp(priv.N) == 1 { // c < N
		return nil, ErrLargeCipher
	
	pminuse1 := new(big.Int).Sub(priv.P, one)

	// c^(p-1) mod p^2
	a := new(big.Int).Exp(c, pminuse1, priv.PSquared)

	// L1(a) = (a - 1) / p
	l1 := new(big.Int).Div(
		new(big.Int).Sub(a, one),
		priv.P,
	)

	// L2(b) = (b-1) / p
	l2 := new(big.Int).Div(
		new(big.Int).Sub(priv.GD, one),
		priv.P,
	)

	// b^(-1) mod p
	binverse := new(big.Int).ModInverse(l2, priv.P)

	// m = L(a*b^(-1) mod p^2) mod p
	m := new(big.Int).Mod(
		new(big.Int).Mul(l1, binverse),
		priv.P,
	)
	return m.Bytes(), nil


func (pub *PublicKey) HomomorphicEncTwo(c1, c2 []byte) ([]byte, error) {
	cipherA := new(big.Int).SetBytes(c1)
	cipherB := new(big.Int).SetBytes(c2)
	if cipherA.Cmp(pub.N) == 1 && cipherB.Cmp(pub.N) == 1 { // c < N
		return nil, ErrLargeCipher
	

	// C = c1*c2 mod N
	C := new(big.Int).Mod(
		new(big.Int).Mul(cipherA, cipherB),
		pub.N,
	)
	return C.Bytes(), nil


func (pub *PublicKey) HommorphicEncMultiple(ciphers ...[]byte) ([]byte, error) {
	C := one

	for i := 0; i < len(ciphers); i++ {
		cipher := new(big.Int).SetBytes(ciphers[i])
		if cipher.Cmp(pub.N) == 1 { // c < N
			return nil, ErrLargeCipher
		
		// C = c1*c2*c3...cn mod N
		C = new(big.Int).Mod(
			new(big.Int).Mul(C, cipher),
			pub.N,
		)
	
	return C.Bytes(), nil
