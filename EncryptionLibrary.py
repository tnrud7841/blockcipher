from Crypto.Cipher import AES
import hashlib
import binascii, os, random, struct
from tkinter import filedialog
import tkinter



def padding(pt_bytes):
    pad_size = 16 - len(pt_bytes) % 16 #패딩할 길이 구함
    pad = pad_size.to_bytes(1, byteorder='big', signed = True) * pad_size
    pt_bytes += pad # 패딩한다!
    return pt_bytes

def encrypt_bytes(key, mode, iv, pt_bytes):
    pt_bytes = padding(pt_bytes)
    cipher = AES.new(key, mode, iv)
    return cipher.encrypt(pt_bytes)

def decrypt_bytes(key, mode, iv, pt_bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    dst_bytes = cipher.decrypt(pt_bytes)
    pad_len = dst_bytes[len(dst_bytes)-1]
    return dst_bytes[:len(dst_bytes)-pad_len]
'''
def ecb_encrypt_bytes(key, pt_bytes):
    n = (int)(len(pt_bytes)/16)
    cipher = AES.new(key, AES.MODE_ECB)
    c = []
    for i in range(n-1): #N은 비트 단위 AES-128/192/256, DES-64
        c[i] = cipher.encrypt(key, pt_bytes[i])
        return c

def ecb_decrypt_bytes(key, c):
    n = (int)(len(pt_bytes)/16)
    ciper = AES.new(key, AES.MODE_ECB)
    p = []
    for i in range(n-1):
        p[i] = cipher.decrypt(key, ciper[i])
        return p[i]
'''
def cbc_encrypt_bytes(key, iv, pt_bytes):
    c = []
    n = (int)(len(pt_bytes)/16)
    c[0] = iv
    cipher = AES.new(key, AES.MODE_CBC)
    for i in (n-1):
        c[i] = cipher.encrypt(key, pt_bytes[i] ^ c[i-1])
    return c

def cbc_decrypt_bytes(key, iv, c):
    p = []
    n = (int)(len(pt_bytes)/16)
    c[0] = iv
    cipher = AES.new(key, AES.MODE_CBC)
    for i in (n-1):
        p[i] = c[i-1]^cipher.decrypt(key,c[i])
    return p   
'''
def ofb_encrypt_bytes(key, iv, pt_bytes):
    t = iv
    c = []
    n = (int)(len(pt_bytes)/16)
    cipher = AES.new(key, AES.MODE_OFB)
    for i in n-2:
        t = cipher.encrypt(key,t)
        c[i] = pt_bytes[i] ^ t #복호화할 때는 c와 pt_bytes 값만 바꾸기
    t = cipher.encrypt(key,t)
    c[n-1] = pt_bytes[n-1] ^ t[: len(pt_bytes[n-1])] #복호화할 때는 c와 pt_bytes 값만 바꾸기
    return c  #복호화할 때는 c와 pt_bytes 값만 바꾸기

def cfb_encrypt_bytes(key, iv, pt_bytes):
    c = []
    c[0] = iv
    n = (int)(len(pt_bytes)/16)
    cipher = AES.new(key, AES.MODE_CFB)
    for i in n-2:
        c[i] = pt_bytes[i] ^ cipher.encrypt(key,c[i-1])  #복호화할 때는 c와 pt_bytes 값만 바꾸기
    c[n-1] = pt_bytes[n-1] ^ (cipher.encrypt(key,c[n-2])[:len(pt_bytes[n-1])])  #복호화할 때는 c와 pt_bytes 값만 바꾸기
    return c  #복호화할 때는 c와 pt_bytes 값만 바꾸기

def ctr_encrypt_bytes(key, iv, pt_bytes):
    c = []
    ctr = iv
    n = (int)(len(pt_bytes)/16)
    cipher = AES.new(key, AES.MODE_CTR)
    for i in n-2:
        c[i] = pt_bytes[i] ^ cipher.encrypt[key,ctr] #복호화할 때는 c와 pt_bytes 값만 바꾸기
        ctr = [ctr+i] % 2**n
    c[n-2] = pt_bytes[n-2] ^ (cipher.encrypt(key,ctr)[: len(pt_bytes[n])]) #복호화할 때는 c와 pt_bytes 값만 바꾸기
    return c #복호화할 때는 c와 pt_bytes 값만 바꾸기
'''
pt_bytes = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710") 
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

print(binascii.hexlify(pt_bytes))
dst = encrypt_bytes(key, cbc_encrypt_bytes, iv, pt_bytes)
print(binascii.hexlify(dst))
dst2 = decrypt_bytes(key, cbc_decrypt_bytes,iv, dst)
print(binascii.hexlify(dst2))
print(pt_bytes == dst2)

'''
Test Vector (NIST SP800-38a)
Key 2b7e151628aed2a6abf7158809cf4f3c

IV 000102030405060708090a0b0c0d0e0f

Plaintext 6bc1bee22e409f96e93d7e117393172a
ae2d8a571e03ac9c9eb76fac45af8e51
30c81c46a35ce411e5fbc1191a0a52ef
f69f2445df4f9b17ad2b417be66c3710.

[ECB]

Block #1
Plaintext 6bc1bee22e409f96e93d7e117393172a
Ciphertext 3ad77bb40d7a3660a89ecaf32466ef97

Block #2
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Ciphertext f5d3d58503b9699de785895a96fdbaaf

Block #3
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Ciphertext 43b1cd7f598ece23881b00e3ed030688

Block #4
Plaintext f69f2445df4f9b17ad2b417be66c3710
Ciphertext 7b0c785e27e8ad3f8223207104725dd4

[CBC]

Block #1
Plaintext 6bc1bee22e409f96e93d7e117393172a
Ciphertext 7649abac8119b246cee98e9b12e9197d

Block #2
Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
Ciphertext 5086cb9b507219ee95db113a917678b2

Block #3
Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
Ciphertext 73bed6b8e3c1743b7116e69e22229516

Block #4
Plaintext f69f2445df4f9b17ad2b417be66c3710
Ciphertext 3ff1caa1681fac09120eca307586e1a7

'''
