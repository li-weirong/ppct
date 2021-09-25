import sys
import gmpy2
import pybloom_live
import os
from print_time import print_time
from Crypto.PublicKey import RSA
QLIST = list(range(0, 1024)) # 作为服务端集合的内容
# RSA参数
RSA_BITS = 2048
RSA_EXPONENT = 65537

@print_time
def generate_private_key(bits=RSA_BITS, e=RSA_EXPONENT):
    private_key = RSA.generate(bits=bits, e=e)
    public_key = private_key.publickey()
    pbf = open('publickey.pem','wb')
    pbf.write(public_key.exportKey('PEM')) # 导出公钥
    pbf.close()
    pvf = open('privatekey.pem','wb')
    pvf.write(private_key.exportKey('PEM')) # 导出私钥
    pvf.close()
    return private_key

def import_private_key():
    f = open('privatekey.pem','r')
    private_key = RSA.importKey(f.read())
    return private_key

@print_time
def setup_bloom_filter(private_key, data_set):
    mode = pybloom_live.ScalableBloomFilter.SMALL_SET_GROWTH
    bf = pybloom_live.ScalableBloomFilter(mode=mode)
    for q in data_set:
        sign = gmpy2.powmod(q, private_key.d, private_key.n) # 签名
        bf.add(sign) # 加入布隆过滤器
    bff = open('bloomfilter.raw','wb')
    bf.tofile(bff) # 将布隆过滤器序列化到本地文件
    bff.close()        
    return bf

def import_blind_data():
    A = []
    f = open('blinddata.raw','r')
    for line in f:
        A.append(gmpy2.mpz(line))
    f.close()
    return A

@print_time
def sign_blind_data(private_key, A):
    B = []
    sbdf = open('signedblinddata.raw','w')
    for a in A:
        sign = gmpy2.powmod(a, private_key.d, private_key.n) # 盲签名
        B.append(sign)
        sbdf.writelines(f"{sign.digits()}\n") # 将签名后的数据序列化到本地文件
    sbdf.close()
    return B

def share_blind_sign():
    print(f"[MOCK] shared blind sign data size:{os.path.getsize('signedblinddata.raw')}")
    print(f"[MOCK] shared bloom filter data size:{os.path.getsize('bloomfilter.raw')}")

if __name__ == '__main__':
    if sys.argv[1] == 'step1':
        generate_private_key()
    elif sys.argv[1] == 'step3':
        private_key = import_private_key()
        setup_bloom_filter(private_key, QLIST)
    elif sys.argv[1] == 'step5':
        private_key = import_private_key()
        A = import_blind_data()
        B = sign_blind_data(private_key, A)
        share_blind_sign()
    else:
        print("Incorrect arguments!")