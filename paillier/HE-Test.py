from phe import paillier
public_key, private_key = paillier.generate_paillier_keypair()
a = 3.141592653
b = 300
encrypted_a = public_key.encrypt(a)
encrypted_b = public_key.encrypt(b) * 2 # paillier支持数乘
encrypted_c = encrypted_a + encrypted_b # paillier支持加法同态
print(private_key.decrypt(encrypted_c))