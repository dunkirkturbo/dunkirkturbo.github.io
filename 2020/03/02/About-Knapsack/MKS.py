#!/usr/bin/env python
# coding: utf-8

# In[8]:


from Crypto.Util.number import *

def GenKey(n):
    a1, b1, e1 = getRandomNBitInteger(16), getRandomNBitInteger(16), getRandomNBitInteger(16)
    A, B, E = [a1], [b1], [e1]
    a, b, e = a1, b1, e1
    sum_a, sum_b, sum_e = a, b, e
    tmp = 2 ** (n - 1)
    for i in range(n - 1):
        a = getRandomRange(sum_a // 2, sum_a)
        b = getRandomRange(sum_b // 2, sum_b)
        met = -a * b + sum_a * sum_b + sum_e - (tmp - 2 ** (i + 1)) * (b1 * (a - sum_a) + a1 * (b - sum_b))
        e = met + getRandomRange(2**8, 2**16)
        sum_a += a
        sum_b += b
        sum_e += e
        A.append(a)
        B.append(b)
        E.append(e)
    p = (sum_a * sum_b + sum_e) + getRandomRange(2**8, 2**16)
    s = size(p) // 2
    u, v = getPrime(s), getPrime(s)
    while GCD(u, p) != 1 or GCD(v, p) != 1:
        u, v = getPrime(s), getPrime(s)
    F = [(u * _) % p for _ in A]
    G = [(v * _) % p for _ in B]
    H = [(u * v * _) % p for _ in E]
    return (A, B, E, p, u, v), (F, G, H)


# In[9]:


(A, B, E, p, u, v), (F, G, H) = GenKey(512)


# In[10]:


m = b"flag{@_v3ry_1o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0o0og_Me4n1ngl3ss_f14g}"


# In[11]:


def encrypt(pubkey, m):
    F, G, H = pubkey
    n = len(F)
    m = [int(_) for _ in bin(bytes_to_long(m))[2:]]
    m = [0] * ((8 - len(m) % 8) % 8) + m
    c = []
    for i in range(0, len(m), n):
        block_m = m[i : i + n]
        if len(block_m) != n:
            padding = [getRandomRange(0, 2) for _ in range(n - len(block_m))]
            block_m += padding
        fm, gm, hm = 0, 0, 0
        for i in range(n):
            fm += F[i] * block_m[i]
            gm += G[i] * block_m[i]
            hm += H[i] * block_m[i]
        block_c = fm * gm + hm
        c.append(hex(block_c)[2:])
    return c


# In[12]:


c = encrypt((F, G, H), m)


# In[15]:


def decrypt(prikey, c):
    A, B, E, u, v, p = prikey
    n = len(A)
    u_inv = inverse(u, p)
    v_inv = inverse(v, p)
    m = ""
    for block_c in c:
        block_m = ""
        Dc = (u_inv * v_inv * int(block_c, 16)) % p
        am, bm, em = 0, 0, 0
        for k in range(n - 1, -1, -1):
            d = (am + A[k]) * (bm + B[k]) + (em + E[k])
            if Dc >= d:
                block_m += "1"
                am += A[k]
                bm += B[k]
                em += E[k]
            else:
                block_m += "0"
        m = m + block_m[::-1]
    return long_to_bytes(int(m, 2))


# In[16]:


decrypt((A, B, E, u, v, p), c)

