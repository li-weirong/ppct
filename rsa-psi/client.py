import secrets
import sys
import gmpy2
import os
from pybloom_live import ScalableBloomFilter
from Crypto.PublicKey import RSA
from print_time import print_time

PLIST = list(range(0, 1024, 249)) # 作为客户端集合的内容
RF_COUNT = max(1024, len(PLIST)) # 生成随机数的个数

@print_time
def generate_random_factors(public_key): #根据公钥计算盲因子
    random_factors = []
    rff = open('randomfactors.raw','w')
    for _ in range(RF_COUNT):
        r = secrets.randbelow(public_key.n) # 生成随机数
        r_inv = gmpy2.invert(r, public_key.n) # 求r的逆元
        r_encrypted = gmpy2.powmod(r, public_key.e, public_key.n) # 公钥加密r
        random_factors.append((r_inv, r_encrypted))
        rff.writelines(f"{r_inv.digits()}\n") # 将盲因子序列化到本地文件
        rff.writelines(f"{r_encrypted.digits()}\n")
    rff.close()             
    return random_factors

def import_public_key():
    f = open('publickey.pem','r')
    public_key = RSA.importKey(f.read())
    return public_key

def import_random_factors():
    random_factors = []
    f = open('randomfactors.raw','r')
    i = 0
    for line in f:
        if i == 0:
            r_inv = gmpy2.mpz(line)
            i = 1
        else:
            r_encrypted = gmpy2.mpz(line)
            random_factors.append((r_inv, r_encrypted))
            i = 0
    f.close()
    return random_factors

@print_time
def blind_data(my_data_set, random_factors, n):
    A = []
    bdf = open('blinddata.raw','w')
    for p, rf in zip(my_data_set, random_factors):
        r_encrypted = rf[1]
        blind_result = (p * r_encrypted) % n # 将数据盲化
        A.append(blind_result)
        bdf.writelines(f"{blind_result.digits()}\n")
    bdf.close()
    return A

def import_signed_blind_data():
    B = []
    f = open('signedblinddata.raw','r')
    for line in f:
        sign = gmpy2.mpz(line)
        B.append(sign)
    f.close()
    return B

def import_bloom_filter():
    f = open('bloomfilter.raw','rb')
    bf = ScalableBloomFilter.fromfile(f) # 将布隆过滤器序列化到本地文件
    f.close()
    return bf

@print_time
def intersect(my_data_set, signed_blind_data, 
                random_factors, bloom_filter, public_key):
    n = public_key.n
    result = []
    for p, b, rf in zip(my_data_set, signed_blind_data, random_factors):
        r_inv = rf[0] # 获取之前计算出来的逆元
        to_check = (b * r_inv) % n
        if to_check in bloom_filter: # 检查是否在布隆过滤器中
            result.append(p)
    return result

def share_blind_data():
    print(f"[MOCK] shared data size:{os.path.getsize('blinddata.raw')}")

if __name__ == '__main__':
    public_key = import_public_key()
    if sys.argv[1] == 'step2':
        random_factors = generate_random_factors(public_key)
        blind_data(PLIST, random_factors, public_key.n)
    elif sys.argv[1] == 'step4':
        share_blind_data()
    elif sys.argv[1] == 'step6':  
        signed_blind_data = import_signed_blind_data()
        random_factors = import_random_factors()
        bloom_filter = import_bloom_filter()
        result = intersect(PLIST, signed_blind_data,
                    random_factors, bloom_filter, public_key)
        for i in result:
            print(i)
    else:
        print("Incorrect arguments!")        