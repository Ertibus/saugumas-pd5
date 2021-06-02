# crypto/crypto.py

import math
import random
import csv
import sys
import numpy
import tqdm

E = 65537
CSV_PRIME_DIR = str(sys.path[0]) + "./crypto/primes.csv"
FIRST_PRIME_LIST = numpy.array([
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541
])

def encrypt(text:str, Kpub:tuple):
    enc_val = numpy.array([], dtype='int64')
    with tqdm.tqdm(text, "Using crpytology on message") as pbar:
        for c in pbar:
            enc_val = numpy.append(enc_val, do_crypto(ord(c), Kpub))
    return enc_val

def decrypt(enc_array, Kpvt:tuple):
    dec_val = ""
    with tqdm.tqdm(enc_array, "Decrypting message") as pbar:
        for c in pbar:
            dec_val = dec_val + chr(do_crypto(c.item(), Kpvt))
    return dec_val


def do_crypto(c:int, key:tuple):
    return pow(c, key[1], key[0])


def is_prime(n:int):
    if type(n) is not int:
        print(type(n))
        raise ValueError("Only natural numbers can be prime!")
    if n > 941:
        for i in FIRST_PRIME_LIST:
            if not n % i:
                return False
    elif n not in FIRST_PRIME_LIST:
        return False

    return True


def calculate_keys(p:int, q:int):
    print("Calculating keys...")
    global E

    if not is_prime(p):
        raise ValueError("p:%i is not a prime number" % (p))
    if not is_prime(q):
        raise ValueError("q:%i is not a prime number" % (q))

    n = p * q
    phi = (p - 1) * (q - 1)

    E = E % phi
    t = EEA(phi, E)
    if t < 0:
        t = t % phi

    pub = (n, E)
    pvt = (n, t)
    return pub, pvt


def find_gcd(a, b):
    if type(a) is not int or type(b) is not int:
        raise ValueError("GCD works only with integer numbers!")
    if a + b == 0:
        raise ZeroDivisionError("Division by zero")

    if a == 0 or b == 0:
        return a + b
    if a == b:
        return a

    if a < b:
        r0, r1 = b, a
    else:
        r0, r1 = a, b

    r2 = r0 % r1

    if r2 != 0:
        return find_gcd(r1, r2)
    else:
        return r1


def EEA(a, b):
    if type(a) is not int or type(b) is not int:
        raise ValueError("EEA works only with integer numbers!")

    if a < b:
        r0, r1 = b, a
    else:
        r0, r1 = a, b

    s0, s1 = 1, 0
    t0, t1 = 0, 1
    ri = 1

    while ri != 0:
        ri = r0 % r1
        qi = (r0 - ri) / r1
        si = s0 - qi * s1
        ti = t0 - qi * t1

        if ri != 0:
            s0, s1 = s1, si
            t0, t1 = t1, ti
            r0, r1 = r1, ri

    return int(t1)


def n_to_primes(n):
    if type(n) is not int:
        raise ValueError("n_to_primes works only with integer numbers!")

    if abs(n) < 4:
        return (0, 0)

    if abs(n) <= 292681:  # 541*541
        prime_set = FIRST_PRIME_LIST
    else:
        prime_set = set()
        with open(CSV_PRIME_DIR, "r", newline="") as file:
            prime_file = csv.reader(file, delimiter=",")
            for prime_line in prime_file:
                for prime in prime_line:
                    if prime == "":
                        continue
                    prime_set.add(int(prime))

    for p in prime_set:
        if p * 2 > n:
            continue
        q = math.floor(n / p)
        if (not n % p) and (is_prime(q)):
            return (q, p) if q > p else (p, q)

    return (0, 0)
