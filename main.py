import random
import math

#group we will be using for the keys
p = 31
g1 = 7

c=1

#state variables
def ratchetInitialize():
	return 1


def modexpo(a,b,c):
	if b==0:
		return 1
	if b==1:
		return a%c
	x = modexpo(a,int(b/2),c)
	v1 =  (x*x)%c
	if b%2==0:
		return v1
	else:
		return (v1*a)%c


#diffie-hellman pair
class keyPair:
	g = 1
	pk = 1
	sk = 1

	def __init__(self, pk1,sk1):
		self.pk = pk1
		self.sk = sk1

def generate_dh():
	sk1 = random.randint(1,p)
	pk1 = modexpo(g1,sk1,p)
	k1 = keyPair(pk1,sk1)
	return k1

def dh(dh_pair,dh_pub):
	v = modexpo(dh_pub,dh_pair.sk,p1)
	return v

def comp_func(a,b):
	return ((a*a)%16+b)%16

def helper(inp,m,message_size):
	r=16
	if m==0:
		return comp_func(inp,message_size)
	if m<16:
		helper(comp_func(inp,m),0,message_size)
	else:
		v = math.log2(m)
		v1 = 2*(2**v)
		return helper(comp_func(inp,m/(v1/r)),m-(v1/r)*(m/(v1/r)),message_size)


def hash(key,offset,message):
	k1 = key*(2**offset)
	message_size = math.log2(message)+1
	x = helper(0,k1*(2**message_size)+message,message_size)
	return x

def hmac(k,m,keyoffset,offset1,offset2):	
	v1 = 2**keyoffset
	inner_key = k%v1
	outer_key = k/v1
	int_value = hash(inner_key,offset1,m)
	return hash(outer_key,offset2,int_value)

def rec(prk,ctx,i,prev,sum):
	if i==16:
		return sum
	new = hmac(prk,prev*32 +ctx*16+i,8,0,0)
	return rec(prk,ctx,i+1,new,sum*16+prev)


def hkdf(xts,skm,ctx):
	prk = hmac(xts,skm,8,0,0)
	k = hmac(prk,ctx*16,8,0,0)
	v = rec(prk,ctx,1,k,k)
	return v




def kdf_rk(rk,dh_out):
	return hkdf(rk,dh_out,1)

def kdf_ck(ck):
	return hmac(ck,c,8,0,0)


if __name__ == '__main__':
	dhs = keyPair(1,1)
	dhs = generate_dh()
