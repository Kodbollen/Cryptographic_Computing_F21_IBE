from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from functools import reduce

class PKG:
    def lagrangian_coefficients(self, S):
        # We only use the basis polynomial (x=0).
        x = 0
        coeff = {}
        for i in S:
            prod = reduce((lambda x, y: x * y), [(x - j) / (i - j) for j in S if i!=j])
            coeff[i] = prod

        return coeff

    def eval_poly(self, coeff, x):
        return sum([coeff[i] * (x ** i) for i in range(len(coeff))])
            
    def __init__(self, attributes, d):
        # We let the PKG have a list of all possible attributes.
        self.group = PairingGroup('SS1024', secparam=512)
        # Set required attribute overlap
        self.d = d
        # Define the universe as the |U| first elements of Zp
        # --- pairing.elements (group.init) needed for charm pair arithmetic.
        zp_elems = [self.group.init(ZR, x) for x in range(1, len(attributes) + 1)]
        self.U = dict(zip(attributes, zp_elems))

        # Choose a random generator and y
        g = self.group.random(G1)
        y = self.group.random(ZR)
        # Choose t_i uniformly at random for i=1,...,|U|
        t = [self.group.random(ZR) for x in range(len(self.U))]
        # Define T_i=g^(t_i)
        T = [g ** x for x in t]
        Y = pair(g, g) ** y

        # Define and return public params and master key
        params = (g, Y, T)
        mk = (y, t)
        self.params = params
        self.master = mk

    def extract(self, attributes, params):
        # Map attribute to Zp element 
        w = [self.U[a] for a in attributes]
        # Generate a d-1 degree random polynomial q -- that is d random coefficients.
        q = [self.group.random(ZR) for x in range(self.d)]
        # enforce q(0)=y -- set first coefficient to y.
        g = params[0]
        y, t = self.master
        q[0] = y
        # Define components D_i=g^(q(i) / t_i)
        D = {i: (g ** (self.eval_poly(q, i) / t[int(i)-1])) for i in w}
        # --> Note: i-1 since t is 0-indexed and our universe is 1,...,|U|.
        
        return D

    def encrypt(self, pub_key, M, params):
        # wp is the public key (required attributes) and M a message as a G2 element.
        wp = [self.U[a] for a in pub_key]
        # Choose random s in Zp
        s = self.group.random(ZR)
        Y, T = params[1:]
        # Create ciphertext:
        # E' = MY^s
        Ep = M * (Y ** s)
        E = {i: T[int(i)-1] ** s for i in wp}

        return (wp, Ep, E)

    def decrypt(self, cipher, private_key, attributes):
        D = private_key
        wp, Ep, E = cipher
        w = [self.U[a] for a in attributes]
        
        attr_intersection = list(set(w).intersection(set(wp)))
        # test |w cap w'| >= d
        assert len(attr_intersection) >= self.d, 'Invalid private key!'

        # Choose an arbitrary d-element subset S of
        S = [attr_intersection[i] for i in range(self.d)]
        coeff = self.lagrangian_coefficients(S)

        # E'/ prod(e(D_i, E_i)^\Delta_{i,S}(0))        
        return Ep / reduce((lambda x, y: x * y), [pair(D[i], E[i]) ** coeff[i] for i in S])

class Party:
    def __init__(self, attributes, pkg):
        self.attributes = attributes
        self.pkg = pkg
        self.D = None

    def authenticate_with_pkg(self):
        self.D = self.pkg.extract(self.attributes, self.pkg.params)

    def receive_message(self, cipher):
        return self.pkg.decrypt(cipher, self.D, self.attributes)

    def send_message(self, message, required_attributes):
        return self.pkg.encrypt(required_attributes, message, self.pkg.params)

def main():
    all_attributes = ['student', 'teacher', 'crypto_lover', 'ready_for_christmas', 'ready_for_exam']
    pkg = PKG(all_attributes, 3) # We only require 3 attributes
    Alice = Party(all_attributes[1:], pkg)
    Bob = Party([all_attributes[0]] + all_attributes[2:4], pkg) # Bob is not a teacher nor ready for exam :(

    # Retrieve Private keys (d_ID) from PKG
    Bob.authenticate_with_pkg()

    # Alice encrypts to Bob
    M = pkg.group.random(GT) # random messages are nice
    cipher = Alice.send_message(M, all_attributes)
    print('Alice sends cipher:\n{}\n'.format(cipher))
    
    message = Bob.receive_message(cipher)
    
    if message:
        print('Bob decrypts message:\n{}\n'.format(message))
        print('Consistency check (Decrypt(cipher)==M): {}'.format(message == M))
    else:
        print('Unsuccesful decryption :(')

if __name__ == '__main__':
    main()
