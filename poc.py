from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.math.integer import randomBits, integer, bitsize
from charm.toolbox.hash_module import Hash, int2Bytes, integer


'''
Design idea:
Classes: PKG, Party
All parties are instantiated with the same PKG instance.
'''

class PKG:
    def __init__(self, security_parameter=512):
        # Setup step 1:
        # Run \mathcal{G} on input k to generate a prime q, two groups G1, G2 of order q
        #   and admissable map G1xG1->G2:
        # // k=512 is default in Pairinggroup - should be changed to 100 post 'exTNF'.
        # self.group = PairingGroup('MNT224', secparam=security_parameter)
        self.group = PairingGroup('SS1024', secparam=security_parameter)
        # Charm library of hashToZr, hashToZn functions
        self.hashings = Hash(self.group) 

        # Choose random generator P\in G1
        self.P = self.group.random(G1)
        # Setup step 2:
        # Pick random s\in Zq and set P_pub=sP
        self.s = self.group.random(ZR) # masterkey
        self.P_pub = self.s * self.P
        # Setup step 3:
        # Choose cryptographic hash functions H1', H2, H3, H4, and an admissable encoding L
        # --> Provided by group.hash(obj, group), i.e. self.group.hash('asdf', G1)

    def extract(self, ID):
        Q_ID = self.group.hash(ID, G1)
        d_ID = self.s * Q_ID
        return d_ID

    def encrypt(self, M, ID):
        Q_ID = self.group.hash(ID, G1)
        # set g_ID=ê(Q_ID, P_pub)\in G2
        g_ID = pair(Q_ID, self.P_pub)
        # choose random \sigma\in{0,1}^n where n is given by security parameter k.
        sigma = integer(randomBits(self.group.secparam))
        # set r = H3(sigma, M)
        r = self.hashings.hashToZr(sigma, M)

        M_encoded = integer(M)

        # C = <U,V,W>
        #   = <rP, sigma xor H2(g_id^r, M xor H4(sigma)>
        U = r * self.P
        V = sigma ^ self.hashings.hashToZn(g_ID ** r)
        W = M_encoded ^ self.hashings.hashToZn(sigma)
        return [U, V, W]
        # return {'U': U, 'V': V, 'W': W}

    def decrypt(self, C, d_ID):
        U, V, W = C
        # sigma = V xor H2(ê(d_ID, U))
        sigma = V ^ self.hashings.hashToZn(pair(d_ID, U))
        # M = W xor H4(sigma)
        M_encoded = self.hashings.hashToZn(sigma) ^ W
        M = int2Bytes(M_encoded)

        # set r=H3(sigma, M)
        r = self.hashings.hashToZr(sigma, M)
        # test U = r * P and reject if not
        if U == r * self.P:
            return M
        else:
            return None

def main():
    t_ID = 'anders@bladefoged.com'
    pkg = PKG(512)

    # Alice encrypts to Balladefoged
    M = b'pls see my message'
    C = pkg.encrypt(M, t_ID)
    print('Ciphertext:\n{}\n'.format(C))

    # Bollen decrypts
    d_ID = pkg.extract(t_ID)

    M = pkg.decrypt(C, d_ID)
    if M:
        print('Successful decryption!\nMessage:\n{}\n'.format(M))
    else:
        print('Unsuccesful decryption :(')

if __name__ == '__main__':
    main()
