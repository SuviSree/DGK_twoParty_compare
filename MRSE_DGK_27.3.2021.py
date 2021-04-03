#---------------------------------------------------------------------
from secrets import randbits
from typing import Tuple
from math import gcd
from gmpy2 import bit_set, is_prime, next_prime
from utils import int_to_mpz, crm, inv_mod, pow_mod
from gmpy2 import mpz
from secrets import randbelow
from helpDGK import DGK_key_gen, DGK_encrypt, DGK_decrypt

#original c++ link: https://github.com/mayank0403/Damgard-Secure-Comparison-Protocol/blob/master/RunningOnSingleMachineCode.cpp
# java implementation: https://github.com/AndrewQuijano/Homomorphic_Encryption/blob/master/Java_PHE/src/main/java/security/DGK/DGKKeyPairGenerator.java
#thesis paper https://beta.vu.nl/nl/Images/stageverslag-blom_tcm235-383790.pdf
#pg 9 of thesis paper


l = 16 #param l - sets size of plaintext
t = 160 #param t - security parameter
k = 1024 #param k - number of bits of keys


def decimalToBinary(n):
    return "{0:b}".format(int(n))


def bob_part1(y, pubK, priK): #y is int #only b has the keys of DGK 
	print("inside bob's 1st part")
	if y.bit_length() > l: #y must be less than 2^l
		print("ERROR: y must be less than 2^l")
		return
	ybin2=decimalToBinary(y)	
	ybin=ybin2[::-1]
	print("bob's share", y, ybin)
	# print("binary of bob's share", ybin)
	# print("length of binary of y", len(ybin))
	C =[]
	#Step 1: Bob sends encrypted bits to Alice

	# c=0
	EncY ={}
	for i in range(0, len(ybin)):
		# print("at i=", i, "ybin=", ybin[i])
		cip=DGK_encrypt(pubK,int(ybin[i]))
		# print(cip)
		EncY[i]=mpz(cip)
		# c+=1
		# i+=1
	print("the encrypted bits of y", EncY)

	print("------------------end of encryption BOB step 1-----------------")
	return EncY

def Alice_part1(x, EncY, pubK):
	x_i_xor_y_i={}
	# c=0
	print("Alice's share", x)
	print("Encrypted Y got from BOB", EncY)
	xbin2=decimalToBinary(x)
	xbin=xbin2[::-1]
	#// Step 2: compute Encrypted X XOR Y
	for i in range(0, len(EncY)):
		if int(xbin[i])==0:
			#x_i_xor_y_i[c]=EncY[i]
			x_i_xor_y_i[i]=EncY[i]
			#c+=1
		elif int(xbin[i])==1:
			enc_one=DGK_encrypt(pubK, 1)
			inv_y_i=inv_mod(EncY[i],pubK.n)
			#x_i_xor_y_i[c]=enc_one*inv_y_i % pubK.n
			x_i_xor_y_i[i]=(enc_one*inv_y_i) % pubK.n
			#c+=1
	print(" STEP 2: xor of x_i_xor_y_i", x_i_xor_y_i)

	#// Step 3: Alice picks deltaA and computes s
	deltaA = randbits(1)
	print("Alice's Secret share-----------", deltaA)
	s=1-(2*deltaA)
	print("alice's S----------------------", s)

	#// Step 4: Compute C_i
	AliceCt = {}
	for i in range(0, len(EncY)):

		prod=1
		for j in range(i+1, pubK.l):
			prod=(prod*x_i_xor_y_i[j]) %pubK.n
		prod_cube=pow_mod(prod,3, pubK.n)
		enc_s=DGK_encrypt(pubK, s)
		enc_x_i=DGK_encrypt(pubK, int(xbin[i]))
		inv_y_i=inv_mod(EncY[i],pubK.n)
		#[c_i] = [s].[x_i].[y_i]^(-1).(prod)
		#AliceCt[i]=(enc_s*enc_x_i*inv_y_i*prod_cube) % pubK.n
		temp1=(enc_s*enc_x_i) % pubK.n
		temp2=(temp1*inv_y_i) % pubK.n
		temp3=(temp2*prod_cube) % pubK.n
		AliceCt[i]=temp3
	print("end of step 4-------ALiceCt-------------", AliceCt)
	print("---------------------Alice Step 5-------------------------------")
	AliceCt_r = {}
	while(True):
		r=randbelow(pubK.u) + 1
		rbin=decimalToBinary(r)
		if len(rbin)==len(AliceCt): break
	print("length of rbin", len(rbin))
	#r1=randbits(2*t)
	#r1bin=decimalToBinary(r1)
	#print("length of r'bin", len(r1bin))
	print("length of AliceCt", len(AliceCt))
	print("--------------Blinding added in Alice", r)
	#if len(rbin)==len(AliceCt) and len(r1bin)==len(AliceCt) : print("--------------LENGTH EQUAL------------------------------") 
	for i in range(0, len(AliceCt)):
		#temp8=pow_mod(AliceCt[i], int(rbin[i]), pubK.n)
		#temp9=pow_mod(pubK.h, int(r1bin[i]), pubK.n)
		#AliceCt_r[i]=(temp8*temp9) % pubK.n
		#--------------attemp1
		#AliceCt_r[i]=AliceCt[i]*DGK_encrypt(pubK,int(rbin[i]))  pubK.n)
		#--------------
		#AliceCt_r[i]=pow_mod(AliceCt[i],int(rbin[i]),pubK.n )
		AliceCt_r[i]=pow_mod(AliceCt[i],r,pubK.n )
		#THIS IS ESSENTIALLY MAKING IT g^(mr).h^r. this is corect. 
		#r ke encrypt kore g er mathae tulle bhul hoe jabe. 
		
	print("randomised AliceCt_r=", AliceCt_r)
	print("end of Alice--------------------")
	return AliceCt_r, deltaA

def bob_part2(AliceCt_r, pubK, priK):
	dec_Alice_ct_r={}
	v=priK.v_p*priK.v_q
	flag=0
	deltaB=-1
	for i in range(0, len(AliceCt_r)):
		#dec_Alice_ct_r[i]=DGK_decrypt(priK,AliceCt_r[i],pubK)
		temp=int(DGK_decrypt(priK,AliceCt_r[i],pubK))
		if temp==0:
			print("decrypted alice_ct_r is 0", temp)
			deltaB=1
			flag+=1
			break
		if flag==0:
			deltaB=0
		print("uyfguydhfee---------inside DEcrypt -----AliceCt_r[i]", AliceCt_r[i])
		# print("uyfguydhfee---------inside DEcrypt dec_AliceCt_r[i]", dec_Alice_ct_r[i])	
		#dec_Alice_ct_r[i]=pow_mod(AliceCt_r[i], v, pubK.n)
	
	# for i in range(0, len(dec_Alice_ct_r)):
	# 	if dec_Alice_ct_r[i]==0:
	# 		print("decrypted alice_ct_r is 0", dec_Alice_ct_r[i])
	# 		deltaB=1
	# 		flag+=1
	# 		break
	# if flag==0:
	# 	deltaB=0
	print("deltaB=", deltaB)
	print("end of step 6----------------------")
	return deltaB
 





if __name__ == "__main__":
	#generate two random l bit number
	while(True):
		x=randbits(l)
		y=randbits(l)
		#if x!=y: break #x and y cannot be equal numbers
		if x.bit_length()==y.bit_length() and x.bit_length()==l and y.bit_length()==l and x!=y and y<pow(2,l) and x>0: break #generate e exact bit length er
		
	print("x=",x)
	print("y=",y)
	print("bit length of x", x.bit_length())
	print("bit length of y", y.bit_length())
	print("-------------------MAKE x and y both of same l length, otherwise ERROR-------------")
	# x_str=str(x)
	# zero_filled_x = x_str.zfill(l)
	# y_str=str(y)
	# zero_filled_y = y_str.zfill(l)
	# x_fin=int(zero_filled_x)
	# y_fin=int(zero_filled_y)

	# print("MAIN func thekei same length kore pathate hobe x and y ke")
	# x_bin=decimalToBinary(x)
	# y_bin=decimalToBinary(y)

	# print("length of x_bin",len(x_bin))
	# print("length of y_bin",len(y_bin))
	# print("Alice: x_fin=",x_bin)
	# print("Bob: y_fin=",y_bin)

	pubK,priK=DGK_key_gen()
	EncY=bob_part1(y,pubK,priK) #dictionary of CTs of bits
	Alice_ct_r, deltaA=Alice_part1(x, EncY, pubK)
	deltaB=bob_part2(Alice_ct_r, pubK, priK)
	print("--------------------END of DGK------------------")
	res=deltaA^deltaB
	print("x=", x, "y=", y, "deltaA=", deltaA, "deltaB=", deltaB, "deltaA XOR deltaB", res)
	#print("--------TEST: result got: if x<y then 1 :: if x>y then 0------------" )
	print("--TEST(after Typo in paper): result got: if x>y then 0 :: if x<y then 1------------" )




#courtesy: bob: https://github.com/AndrewQuijano/Homomorphic_Encryption/blob/8ebcb2b429d48af37fc684bd1434a83f98d1d05f/Java_PHE/src/main/java/security/socialistmillionaire/bob.java#L186
#courtesy: alice: https://github.com/AndrewQuijano/Homomorphic_Encryption/blob/8ebcb2b429d48af37fc684bd1434a83f98d1d05f/Java_PHE/src/main/java/security/socialistmillionaire/alice.java#L91
