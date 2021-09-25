import gmpy2
from Crypto.PublicKey import RSA
RSA_BITS = 2048
RSA_EXPONENT = 65537
private_key = RSA.generate(bits=RSA_BITS, e=RSA_EXPONENT)
public_key = private_key.publickey()
a = 15
b = 5
encrypted_a = gmpy2.powmod(a, public_key.e, public_key.n)
encrypted_b = gmpy2.powmod(b, public_key.e, public_key.n)
encrypted_c = encrypted_a * encrypted_b  # RSA支持乘法同态
decrypted = gmpy2.powmod(encrypted_c, private_key.d, private_key.n)
print(decrypted)