--------------3.4.2021
DGK_enc:
pg 9 of thesis has simplified updated https://beta.vu.nl/nl/Images/stageverslag-blom_tcm235-383790.pdf
https://github.com/mayank0403/Damgard-Secure-Comparison-Protocol  -implementation of the old 3 party protocol. 
base conditons: 
l = 16 #param l - sets size of plaintext
t = 160 #param t - security parameter
k = 1024 #param k - number of bits of keys
Additive homomorphic bit wise public key encryption.
if Ct^v = 1 mod n ==> msg =0.
[indepdently this file also exists in https://github.com/SuviSree/DGK ]
-----------------------------------------------
DGK-compare
https://eprint.iacr.org/2018/1100.pdf - protocol 1
https://github.com/AndrewQuijano/Homomorphic_Encryption
--protocol 1 of this
Result : 2 party interactive protocol
ip: x,y. [conditions: bitLength(x)==bitLength(y), 0<x, y<2^l
output: 
--------------------------------------------------
KeyNote: - the binary of the numbers are accessed in the reverse order
-----------------------------------
