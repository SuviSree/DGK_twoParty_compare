from secrets import randbits
from typing import Tuple
from math import gcd
from gmpy2 import bit_set, is_prime, next_prime
from utils import int_to_mpz, crm, inv_mod, pow_mod
from gmpy2 import mpz
from secrets import randbelow

#original c++ link: https://github.com/mayank0403/Damgard-Secure-Comparison-Protocol/blob/master/RunningOnSingleMachineCode.cpp
# java implementation: https://github.com/AndrewQuijano/Homomorphic_Encryption/blob/master/Java_PHE/src/main/java/security/DGK/DGKKeyPairGenerator.java
#thesis paper https://beta.vu.nl/nl/Images/stageverslag-blom_tcm235-383790.pdf
#pg 9 of thesis paper


l = 16 #param l - sets size of plaintext
t = 160 #param t - security parameter
k = 1024 #param k - number of bits of keys

#Initialize DGK Key pair generator and sets DGK parameters

#final HashMap <Long, BigInteger> gLUT = new HashMap<Long, BigInteger>()
HashM_g = {}
HashM_h = {}

def generategLUT(pubK, privK):	
	gvp=pow_mod(pubK.g, privK.v_p, privK.p)
	for i in range(0,pubK.u):
		out = pow_mod(gvp, i, privK.p)
		HashM_g[out]=i
		#mapping(g^m --------> m )
		i+=1
	#0 to u, sobar g^(0), .... g^(1), g^(2), ...., g^(u), value pre-compute kore rekhe deo
	#LEARNING --- do not store just g^0, g^1, ..... , g^u
	# store   (g^vp)^0, (g^vp)^1, (g^vp)^2, (g^vp)^3,................., (g^vp)^u
		



class pubKey(object):
    def __init__(self, n,g,h,u,l,t,k):
        self.n = n
        self.g = g
        self.h = h
        self.u = u
        self.l = l
        self.t = t
        self.k = k



class privKey(object):
    def __init__(self, p,q,v_p, v_q, pubKey):
        self.p = p
        self.q = q
        self.v_p = v_p
        self.v_q = v_q
        self.pubKey = pubKey


def DGK_storePub(pub):
	pub_obj=pubKey(pub.n, pub.g, pub.h, pub.u, pub.l, pub.t, pub.k)
	return pub_obj
	# pub_obj=pub    
def DGK_storePri(pri):
	pri_obj=privKey(pri.p, pri.q, pri.v_p, pri.v_q, pri.pubKey)
	return pri_obj
	# pri_obj=pri     

def gen_prime(n_bits):
    """Returns a prime number with `n_bits` bits.
    :param n_bits: The number of bits the prime number should contain.
    :return: A prime number with `n_bits` bits.
    """
    base = randbits(n_bits)
    base = bit_set(base, n_bits - 1)
    prm = next_prime(base)
    return prm


def DGK_key_gen():
	u=gen_prime(l)
	print("u=", u, " of length l=",l)
	v_p=gen_prime(t)
	v_q=gen_prime(t)
	print("v_p=", v_p, "v_q=", v_q, "of length t=", t)
	v=v_p*v_q
	print("v=v_q*v_p",v)

	#---------------generating p
	tmp=u*v_p
	needed_bitsp = k//2 - (tmp.bit_length())
	print("needed_bits for p",needed_bitsp)


	#p = rp * u * vp + 1
	#u | p - 1
	#vp | p - 1
	while(True):
		rp = randbits(needed_bitsp)
		rp = bit_set(rp, needed_bitsp - 1)
		p=rp*tmp + 1
		if is_prime(p):
			print("p got=", p)
			break


	#--------------generating q
	tmp2=u*v_q
	needed_bitsq = k//2 - (tmp2.bit_length())
	print("needed_bits for q",needed_bitsq)

	#q - 1 | rq * vq * u
	#c^{vp} = g^{vp*m} (mod n) because
	#rq | (q - 1)
	
	while(True):
		rq = randbits(needed_bitsq)
		rq = bit_set(rq, needed_bitsq- 1)
		q=rq*tmp2 + 1
		if is_prime(q):
			print("q got=", q)
			break

	#if (p==q): print("p and q are equal", p,q)


	#------------------------------------generating h
	#Selecting g and h:: g and h should have value less than n and gcd with n = 1 
	
	#Finding h first order of h is vp.vq
	n=p*q
	tmp3=rp*rq*u

	while(True):
		#getting the two random generators g,h of Z_N*
		r = randbits(n.bit_length()) #because the generators must have order n, so n er bit length er nichhi
		#h=pow_mod(mpz(r),mpz(tmp3),mpz(n))    #h = r^{rp*rq*u} (mod n)
		h=pow_mod(r,tmp3,n)
		
		if h==1: continue
		if pow_mod(h,v_p,n)==1: continue #h^{vp}(mod n) = 1
		if pow_mod(h,v_q,n)==1: continue #h^{vq}(mod n) = 1
		if pow_mod(h,u,n)==1: continue #h^{u}(mod n) = 1
		if pow_mod(h,u*v_q,n)==1: continue #h^{u*vq} (mod n) = 1
		if pow_mod(h,u*v_p,n)==1: continue #h^{u*vp} (mod n) = 1
		if gcd(h,n)==1: break
	print("------------------generator h=",h)
	#---------------------------------------h generated

	#---------------------------------------generating g
	rprq=rp*rq
	while(True):
		#getting the two random generators g,h of Z_N*
		r = randbits(n.bit_length()) #because the generators must have order n, so n er bit length er nichhi
		#h=pow_mod(mpz(r),mpz(tmp3),mpz(n))    #h = r^{rp*rq*u} (mod n)
		g=pow_mod(r,rprq,n)
		
		if g==1: continue
		if gcd(g,n)!=1: continue #(g, n) must be relatively prime
		if pow_mod(g,u,n)==1: continue #g^{u} (mod n) = 1
		if pow_mod(g,u*u,n)==1: continue #g^{u*u} (mod n) = 1
		if pow_mod(g,u*u*v_p,n)==1: continue #g^{u*u*vp} (mod n) = 1
		if pow_mod(g,u*u*v_q,n)==1: continue #g^{u*u*vq} (mod n) = 1
		if pow_mod(g,v_p,n)==1: continue #g^{vp} (mod n) = 1
		if pow_mod(g,v_q,n)==1: continue #g^{vq} (mod n) = 1
		if pow_mod(g,u*v_q,n)==1: continue	#g^{u*vq}(mod n) = 1
		if pow_mod(g,u*v_p,n)==1: continue	#g^{u*vp}(mod n) = 1
		if pow_mod(g,v_q*v_p,n)==1: continue#g^{vp*vq} (mod n) == 1
		if pow_mod(g,v_p,p)==1: continue	#g^{vp} (mod p) == 1
		if pow_mod(g,u,p)==1: continue	#g^{u} (mod p) == 1
		if pow_mod(g,v_q,q)==1: continue #g^{vq}(mod q) == 1
		if pow_mod(g,u,q)==1: continue #g^{u}(mod q) ==1
		break

	print("------------------generator g=",g)

	#pubKey =  new DGKPublicKey(n, g, h, u, this.l, this.t, this.k);



	pubK =  pubKey(n, g, h, u, l, t, k)
	#privkey = new DGKPrivateKey(p, q, vp, vq, pubKey);
	privK = privKey(p, q, v_p, v_q, pubK)
	print("generating hashmaps")
	print("public key structure details", pubK)
	print("private key structure details", privK)
	generategLUT(pubK,privK)
	# print("TEST: ---------precomputed hashmap for g", HashM_g)
	
	return pubK, privK


def DGK_encrypt(pubK,m):
	#generate m such that m is less than u
	# print("------------------------------------------encryption-------------------------------")
	# print("bound on message space, u=", pubK.u)
	
	# print("plaintext message", m)
	# print("message generated less than u", m)
	# print(" g of the public key", pubK.g)
	# print("message generated", m)
	# print("n=", pubK.n)
	g_m = pow_mod(pubK.g, m, pubK.n)

	if g_m >= pubK.n : print("g_m is greater than n")

	# print("g_m", g_m)
	rand_length=pubK.t*(5//2)
	r=randbits(rand_length)
	# print("rand_length=", rand_length,"random number", r)
	h_r =pow_mod(pubK.h, r, pubK.n)
	# print("h_r=", h_r)
	if h_r >= pubK.n : print("h_r is greater than n")

	C=g_m*h_r % pubK.n
	# print("ciphertext=", C)
	return C

def DGK_decrypt(privK, C, pubK):
	#c = g^m * h^r (mod n)
	#c^vp (mod p) = g^{vp*m} (mod p), 
	#Because h^{vp} (mod p) = 1
	#Hash maps are built-in in Python, they're called dictionaries:
	#https://www.geeksforgeeks.org/hash-map-in-python/ hashmap in python
	print("---------------------------------------------decryption-----------------------------------------------")
	# CT_vp =pow_mod(C, priK.v_p, privK.p)
	# get_msg=HashM_g[CT_vp]
	# print("plaintext value got from hashmap", get_msg)

	# print("=============================precomputed value for decryption==========================================")
	# print("hash map for values of g created", HashM_g)
	# print("=============================end of generating hash map for g==========================================")
	# print("in python, hashmap=dictionary")

	CT_vp_n =pow_mod(C, privK.v_p, privK.p)
	get_msg2=HashM_g[mpz(CT_vp_n)]
	# if CT_vp_n==g_m: print("CT_vp_n=g_m")
	# get_msg2=HashM_g[g_m]
	print("plaintext value got from hashmap", get_msg2)
	
	return get_msg2







	


	

# if __name__ == "__main__":
# 	pubK,priK=DGK_key_gen()
# 	#CT=encrypt(pubK)
# 	m1=0
# 	m2=1
# 	CT1=DGK_encrypt(pubK,m1)
# 	CT2=DGK_encrypt(pubK,m2)

# 	v=priK.v_p*priK.v_q
# 	print("-----------------------------BACK in main-------------------------------------------")
# 	print(pow_mod(CT1, v, pubK.n))  #if m1=0, then CT^v mod n ==1 
# 	print(pow_mod(CT2, v, pubK.n))
# 	#msg=decrypt(priK,CT1, pubK)




#SIMPLE [Encryption, DECRYPTION] of DGK done -----------------

#now, developt the  party protocol






	
