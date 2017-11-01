How to get the private keys
===
學號：0556186
姓名：Shan-Jung Fu

# RSA 算法  
1. 選擇一對不同的、足夠大的值數 p，q。  
2. 計算 n=pq。  
3. 計算 f(n)=(p-1)(q-1) ，同時對 p, q 嚴加保密，不讓任何人知道。  
4. 找一個與 f(n) 互質的數 e ，且 1<e<f(n)。  
5. 計算 d，使得 de≡1 mod f(n) 。這個公式也可以表達為 d ≡ e-1mod f(n)  
  
# Hacking  
通常在 n1 = a × b, n2 = c × d 的情況下 gcd(n1, n2) = 1   
但倘若 n1 = a × b, n2 = b × c 的情況下 gcd(n1, n2) = b 我們就可以找到相同的公因數。  
已知 e ， 又 a = n1 / b, 則 private key = e−1 (mod (a-1)(b-1)) 就可以取得  private key。  
  
# 程式說明  
## 程式語言  
python2.7  
## 執行方式  
```python=  
$ pip install -r requirements.txt
$ python rsa_attack.py
```
  
## 原程式結構  
```bash
├── publicKeys
│  ├── public1.pub
│  ├── public10.pub
│  ├── public11.pub
│  ├── public12.pub
│  ├── public2.pub
│  ├── public3.pub
│  ├── public4.pub
│  ├── public5.pub
│  ├── public6.pub
│  ├── public7.pub
│  ├── public8.pub
│  └── public9.pub
├── requirements.txt
└── rsa_attack.py
```
  
## 執行程式完後結構  
```bash
├── privateKeys
│  ├── private3.pem
│  └── private8.pem
├── publicKeys
│  ├── public1.pub
│  ├── public10.pub
│  ├── public11.pub
│  ├── public12.pub
│  ├── public2.pub
│  ├── public3.pub
│  ├── public4.pub
│  ├── public5.pub
│  ├── public6.pub
│  ├── public7.pub
│  ├── public8.pub
│  └── public9.pub
├── requirements.txt
└── rsa_attack.py
```
  
# 程式流程  
主程式為 rsa_attack.py ，該程式有相依的 pip library，分別為 requirements.txt 內的 pycrypto 與 gmpy 。  
pycrypto 有許多加密演算法，可以對傳輸的資訊進行加密。在這邊我們使用 RSA 算法進行處理。  
gmpy 是個高度精確的數學運算 library，這邊使用它來計算 d 值。  
  
整個的程式流程進行如下：  
定義 4 個 function ，分別為 get_ne, get_gcd, generate_d, generate_privateKey。  
- get_ne: 存取 public key 的 *.pub 檔案，使用 RSA.importKey 取得每個 public key 的 n 和 e。  
- get_gcd: 傳入 n 的 list ，用兩個 for 迴圈計算 gcd ，若找到大於 1 的 gcd 值，則回傳該值。  
- generate_d: 使用 gmpy 計算 d 值。  
- generate_privateKey: 產出 private key 並寫入檔案 *..pem。  
  
- Main function:  
```python=  
def main():
    # 定義 n 和 e 的 dict
    rsa_n = {}
    rsa_e = {}
    # 將 1 ~ 12 的值分別帶到 get_ne 取得 n 和 e ，並存入 rsa_n 和 rsa_e 的 dict 中
    for num in range(1, 13):
        (n, e) = get_ne(num)
        rsa_n[num] = n
        rsa_e[num] = e
    # 將 dict rsa_n 帶入 get_gcd 取得大於 1 的 gdb 以及是哪個 兩個 key 編號 與 兩個 n 的 pq
    (key_1, key1_p, key_q, key2_p, key_2) = get_gcd(rsa_n)
    # 透過 pq 取得 d1
    d = generate_d(rsa_e[key_1], key1_p, key_q)
    # 用 n, e, d 產出 private key1
    generate_privateKey(key_1, rsa_n[key_1], rsa_e[key_1], d)
    # 透過 pq 取得 d2
    d = generate_d(rsa_e[key_2], key2_p, key_q)
    # 用 n, e, d 產出 private key2
    generate_privateKey(key_2, rsa_n[key_2], rsa_e[key_2], d)
```
  
# Source code  
1. requirements.txt  
  
```
pycrypto
gmpy
```
  
2. rsa_attack.py  
```python=
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
```
