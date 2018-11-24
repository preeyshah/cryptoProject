class state:
	DHs = keyPair()
	DHr, RK, CKs, CKr, Ns, Nr, PN, MKSKIPPED

def RatchetInitAlice(state, SK, bob_dh_public_key):
	state.DHs = GENERATE_DH()
	state.DHr = bob_dh_public_key
	state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
	state.CKr = None
	state.Ns = 0
	state.Nr = 0
	state.PN = 0
	state.MKSKIPPED = {}

def RatchetInitBob(state, SK, bob_dh_key_pair):
	state.DHs = bob_dh_key_pair
	state.DHr = None
	state.RK = SK
	state.CKs = None
	state.CKr = None
	state.Ns = 0
	state.Nr = 0
	state.PN = 0
	state.MKSKIPPED = {}

def RatchetEncrypt(state, plaintext, AD):
	state.CKs, mk = KDF_CK(state.CKs)
	header = HEADER(state.DHs, state.PN, state.Ns)
	state.Ns += 1
	return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))

def RatchetDecrypt(state, header, ciphertext, AD):
	plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
	if plaintext != None:
	return plaintext
	if header.dh != state.DHr:
	SkipMessageKeys(state, header.pn)
	DHRatchet(state, header)
	SkipMessageKeys(state, header.n)
	state.CKr, mk = KDF_CK(state.CKr)
	state.Nr += 1
	return DECRYPT(mk, ciphertext, CONCAT(AD, header))

def TrySkippedMessageKeys(state, header, ciphertext, AD):
	if (header.dh, header.n) in state.MKSKIPPED:
	mk = state.MKSKIPPED[header.dh, header.n]
	del state.MKSKIPPED[header.dh, header.n]
	return DECRYPT(mk, ciphertext, CONCAT(AD, header))
	else:
	return None

def SkipMessageKeys(state, until):
	if state.Nr + MAX_SKIP < until:
	raise Error()
	if state.CKr != None:
	while state.Nr < until:
	state.CKr, mk = KDF_CK(state.CKr)
	state.MKSKIPPED[state.DHr, state.Nr] = mk
	state.Nr += 1
	
def DHRatchet(state, header):
	state.PN = state.Ns
	state.Ns = 0
	state.Nr = 0
	state.DHr = header.dh
	state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
	state.DHs = GENERATE_DH()
	state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))

