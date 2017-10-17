# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
import subprocess
from fractions import gcd
import gmpy


def get_ne(num):
    pubfile = subprocess.check_output(
        "cat publicKeys/public" + str(num) + ".pub", shell=True)
    pub = RSA.importKey(pubfile)
    n = long(pub.n)
    e = long(pub.e)
    return(n, e)


def get_gcd(rsa_n):
    for a, b in rsa_n.iteritems():
        for x, y in rsa_n.iteritems():
            k = gcd(b, y)
            if k != 1 and a != x:
                aa = a
                kk = k
                xx = x
                a_p = b / k
                b_p = y / k
    return (aa, a_p, kk, b_p, xx)


def generate_d(e, p, q):
    d = long(gmpy.invert(e, (p - 1) * (q - 1)))
    print d
    return d


def generate_privateKey(num, rsa_n, rsa_e, d):
    key = RSA.construct((rsa_n, rsa_e, d))
    privateKey = key.exportKey()
    with open("privateKeys/private" + str(num) + ".pem", 'a') as the_file:
        the_file.write(privateKey)


def main():
    rsa_n = {}
    rsa_e = {}
    for num in range(1, 13):
        (n, e) = get_ne(num)
        rsa_n[num] = n
        rsa_e[num] = e
    (key_1, key1_p, key_q, key2_p, key_2) = get_gcd(rsa_n)
    d = generate_d(rsa_e[key_1], key1_p, key_q)
    generate_privateKey(key_1, rsa_n[key_1], rsa_e[key_1], d)
    d = generate_d(rsa_e[key_2], key2_p, key_q)
    generate_privateKey(key_2, rsa_n[key_2], rsa_e[key_2], d)


if __name__ == "__main__":
    main()
