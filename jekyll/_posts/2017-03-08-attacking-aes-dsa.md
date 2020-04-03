---
layout: post
title:  "Attacking AES and DSA"
---

Recently I was involved in a security conference called 
[SecuDay](https://secuday.github.io/) where I have presented 
[Attacking Games for Fun and Profit](https://github.com/DimitriFourny/csgo-hack/blob/master/slides.pdf). 
At the end of the conference, we have been invited to resolve some challenges 
conceived by [Charles Bouillaguet](http://www.lifl.fr/~bouillag/). There was 
three levels, easy and medium level are based on the bruteforce of an 
[Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) 
128-bits encryption and the hard level was to crack a bad implementation of the 
[Digital Signature Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm). 
The same implementation failure of DSA was used to break the Sony PS3.

## Advanced Encryption Standard

AES is an old symmetric-encryption published in 1977. It’s based on multiple 
substitutions and permutations and designed to be fast in both software and 
hardware. We can use a key size of 128, 192 or 256 bits. The idea of this 
challenge is to show that even if AES is effective, a bad choice of the key can 
compromise all the system.

Here, we will use AES in CBC (Cipher Block Chaining) mode. In this mode, each 
block will be encrypted thanks to the previous block. In consequence, the first 
block needs to be calculated: it’s called the IV (Initialization Vector). In 
OpenSSL, the IV is based on a password:

```
IV = md5(md5(password+salt) + password + salt)
```

In addition, a salt will be used. This salt will be generated randomly by 
OpenSSL and it will be used to generate the IV and added in the beginning of the 
encrypted file. In consequence, if we encrypt two times the same file with the 
same password, it will generate two totally different outputs.


## Easy Level

In the first level, we need to bruteforce a file which use a password contained 
in a dictionnary of 45.000 passwords. In consequence, I have used a totally dumb 
method: to launch the OpenSSL shell and test all the passwords. Finally I have 
searched an english text (ASCII only) in all the outputs generated: I have got 
the valid password in less than 5 minutes. “If it looks stupid but it works, 
it’s not stupid”.

```py
# Test all the passwords

import subprocess, os
import time, progressbar

f = open('words.txt', 'r')
words = f.read()
f.close()
words = words.split('\n')

bar = progressbar.ProgressBar(max_value=len(words))
i = 0
file = ''
for key in words:
    bar.update(i)
    i += 1
    file = 'out/'+key+'.txt'

    p = subprocess.Popen(['openssl', 'enc', '-d', '-aes-128-cbc', '-base64', '-pass', 'pass:'+key, '-in', 'easy.txt', '-out', file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if err != b'':
        try: 
            os.remove(file)
        except:
            pass

print('\nend')

# Search the valid output
import os, sys

def is_ascii(s):
    return all(ord(c) < 128 for c in s)

path = "out/"
dirs = os.listdir( path )

for file in dirs:
   f = open(path+file, 'r')

   try:
       buf = f.read()

       if is_ascii(buf):
           print(file)
   except:
       pass
   finally:
       f.close()
```


## Medium Level

For this second level, the idea was the same but the password has been modified. 
One letter has been capitalized and one digit has been inserted. If you use the 
same method, you will get the password in 48 hours: I think that we can do 
something better. I have done all the AES directly in python, including the IV 
calculation. You add the multithreading and you can get the password in less 
than 5 minutes:

```py
import subprocess, os
import time, progressbar
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF1
import hashlib
import threading

def passToKeyIv(password, salt):
    password = password.encode('latin-1')

    md5 = hashlib.md5()
    md5.update(password+salt)
    key = md5.digest()

    md5 = hashlib.md5()
    md5.update(key+password+salt)
    iv = md5.digest()

    return (key, iv)

def is_ascii(s):
    return all(c < 128 for c in s)

def polypassword(password, letter_position, digit_position, digit):
    if password[letter_position].upper() != password[letter_position]:
        password = password[0:letter_position] + password[letter_position].upper() + password[letter_position+1:]
    else:
        password = password[0:letter_position] + password[letter_position].lower() + password[letter_position+1:]
    password = password[0:digit_position] + str(digit) + password[digit_position:]
    return password

def testPassword(words, digit, progress):
    for password_base in words:
        progress[digit] += 1

        for letter_position in range(len(password_base)):
            for digit_position in range(len(password_base)+1):
                password = polypassword(password_base, letter_position, digit_position, digit)

                (key, iv) = passToKeyIv(password, salt)
                aes = AES.new(key, AES.MODE_CBC, iv)
                msg = aes.decrypt(binary[16:])

                if is_ascii(msg):
                    print("\nPassword = "+password)
                    os._exit(0)


f = open('medium.txt', 'r')
text = f.read()
f.close()
binary = base64.b64decode(text)
salt = binary[8:16]

f = open('words.txt', 'r')
words = f.read()
f.close()
words = words.split('\n')

max_bar = len(words) * 10
bar = progressbar.ProgressBar(max_value=max_bar)
progress = [0]*10
msg = ""

for digit in range(10):
    t = threading.Thread(target=testPassword, args = (words, digit, progress))
    t.daemon = True
    t.start()

while True:
    time.sleep(0.1)
    bar.update(sum(progress))
```

```
D:\SecuDay\medium>python attack2.py
 42% (194135 of 454030) |########################                                  | Elapsed Time: 0:04:55 ETA: 0:06:35
Password = handCuff5s
```

I have tested this method for the first level, and I have got the password in 
less than one second:

```
D:\SecuDay\easy>python attack2.py
 33% (15262 of 45403) |####################                                        | Elapsed Time: 0:00:00 ETA: 0:00:01
Password = eventuality
```

To situate the time to replicate this bruteforce, my processor is an 
[Intel Core i7-4790k](http://ark.intel.com/products/80807/Intel-Core-i7-4790K-Processor-8M-Cache-up-to-4_40-GHz) 
(Quad cores, 4.4 Ghz).


## Digital Signature Algorithm

DSA is an algorithm to sign messages. It’s royalty-free and it was published in 1991. 
Like RSA, it's based on the 
[P versus NP problem](https://en.wikipedia.org/wiki/P_versus_NP_problem). The 
DSA signature is composed of two numbers `(r, s)`:

```
r = g^k mod p mod q
s = k^-1 (H(m) + x*r) mod q
```

`p` and `q` are two prime numbers. `x` and `k` are generated randomly and they 
are inferior than `q`. `H(m)` is the hash of the message, here we will use 
SHA-256. This algorithm can be used with OpenSSL. We can verify a message like 
that:

```bash
openssl dgst -sha256 -verify pk.pem -signature message.der message.txt
```

The couple `(k, x)` will be our private key.


## Hard Level

We have a website which generate poems and generate its DSA signature. Of 
course, the website give us one public key to verify the message according to 
the signature. The target was to recover the private key to generate a 
self-signed message which is corresponding to the same public key. When we send 
a request to the server, we get a message in this format:

```json
{
    "poem": "Le vieux marin breton...", 
    "signature": "MEQCICKAWoFX1uNjpdNHYRn31F1feKxXaO9OyFym4UolBE2JAiALqJLv8h7Bypra/jLdDKi38TRgs3l9td54FViWEPU/vA=="
} 
```

It’s actually a JSON message containing our poem and our signature. The 
signature is encoded in base64 and we can recover the couple `(r, s)` by parsing 
the *ASN.1* format. So in consequence, the first step was to extract all these 
information and save them:

```py
import base64, json
import requests
import codecs

def parse_asn1(der):
    vr = 0
    vs = 0

    if der[0] != 0x30:
        raise ValueError("Invalid format header (0x30)")

    # VR
    cursor = 2
    if der[cursor] != 0x02:
        raise ValueError("Invalid VR header (0x02)")

    cursor += 1    
    vr_length = int(der[cursor])

    cursor += 1
    vr = der[cursor : cursor+vr_length]

    cursor += vr_length 
    if der[cursor] != 0x02:
        raise ValueError("Invalid VS header (0x02)")

    cursor += 1
    vs_length = int(der[cursor])

    cursor += 1
    vs = der[cursor:]

    return (vr,vs)

def hex_bignumber(number):
    result = ""
    for n in number:
        result += "%02X" % n

    return result


answer = requests.get(url='http://security.fil.cool/hard/crypto-poet')
data = json.loads(answer.text)
print(data)

signature = data['signature']
signature = base64.b64decode(signature)

# backup
f = open('input.der', 'wb')
f.write(signature)
f.close()
f = codecs.open('poem.txt', 'w', 'utf-8')
f.write(data['poem'])
f.close()

# parse
der = [x for x in signature] # DER format
(vr,vs) = parse_asn1(der)

print("r = "+hex_bignumber(vr))
print("s = "+hex_bignumber(vs))
``` 

After multiple call, we see that the number `r` is always the same. In 
consequence, we can conclude that the number `k` is static:

```
r = g^k mod p mod q
```

If two messages have the same `k`, all the system breaks (the modulation per `q` 
is not done for a better readability):

```
sa = k^-1 (H(ma) + x*r)
sb = k^-1 (H(mb) + x*r)

=> sa - sb = k^-1 [H(ma) + x*r - H(mb) - x*r]
=> sa - sb = k^-1 [H(ma) - H(mb)]
=> k = [H(ma) - H(mb)] / (sa - sb)
```

And now that we have `k`, we can recover `x` (`m` can be the message `A` or `B`):

```
s = k^-1 (H(m) + x*r) mod q
=> x = [(s*k) - H(m)] - r^-1 mod q
```

I have implemented this algorithm with `gmpy2`:

```py
import hashlib, math
from decimal import *
from gmpy2 import is_prime, mpq, powmod

def int_to_hexarray(n):
    n_hex = "%x" % n
    if (len(n_hex) % 2) != 0:
        n_hex = '0' + n_hex

    n_array = [int(n_hex[i:i+2], 16) for i in range(0, len(n_hex), 2)]
    return n_array

#####################
f = open('poem1.txt', 'rb')
poem1 = f.read()
f.close()
s1 = 0x0588B660896F999520217C3A0290A48DDEF103342F30C3AFE69CF88F6275D573

#####################
f = open('poem2.txt', 'rb')
poem2 = f.read()
f.close()
s2 = 0x7B2C4707F3AD96AD93BE8A01F7A8B10F3B0AE7CC148F5F719F1DF28990BBC9B9

#####################
r = 0x22805A8157D6E363A5D3476119F7D45D5F78AC5768EF4EC85CA6E14A25044D89 # the same for poem1 and poem2

# pub info
p = 0x00d899aed2c32937911ea8bdc7dce006cc471a178b908806e6f67d20ccb8017de4f437947d161b5d478f23d98a9ba67118f5b1121ad04db0214fea8b9a23c2cd341dab342ad8b453b771b78b978a0f73ec445d36fb42ee5eff4890753a35cf88eb3b9efa74533a2ef5d69042990f286b8528e6e1bd25ed645febf44cb9f54533fff683ccdbe77a929e883d5a714c61af9f5d745443f7e18ea163ba69012e64096ab3929206b9bfa0ce881f5a4d7d6ac15c93fd4eb4935363b40fe787aa0ceed6f556b7bbcec3c36047ebe2787f0c2f1fcfb4d925b35bfadf0c61cb135684c772c21e9b110b316410d59d5aa94e6c1fda3bb8a4b6550b3e3675f41bd64aea47d323
q = 0x008a8624d936fcf2e1b5f70ec351a4d0184d211e00b11883a5cee71e2b7ffa90a9
g = 0x7c9d027c3b807cc7c7681ea2cd283e8bbf9d0c80a20518584a2b3ffe077a69fc8c045907a56a6f5497b30de96e9fe58ebbae0f64ca52a3da18348b2ba242bf8ae75a73c3bfa6e9154476d306c6cfea7c056da1834c8c441cce3f939b5a1cc0f4d2ed67588c89ec0ba2adfdd1c3c0b1ccb0dba29858b172928f6fbd94c0ea31849c8fb18de7c6df962583ff9a9e36271c6e8f95269b776bc1ecba78d9d51465ff5e2c6332ceb198996c0c6c7c16a63dc115ff4f02ef5fc5ec2e7d2bc8ded843e6abefdfc454e420db1c95194047b06ccb9436267e8630401008907eebc309e320c4514d10702f93fd9dfef0d851f1548c27f0551e92259c908a2aca878fd453a7

# Calculte hashs
h1 = hashlib.sha256(poem1).hexdigest()
h1 = int(h1, 16)
h2 = hashlib.sha256(poem2).hexdigest()
h2 = int(h2, 16)

# Search k
# https://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/
k = (h1 - h2) * powmod(s1 - s2, -1, q)

# Verify k : we recalculate r
verif_r = powmod(g, k, p) % q
print("r = "+str(r))
print("  = "+str(verif_r))

# Search x
# https://rdist.root.org/2009/05/17/the-debian-pgp-disaster-that-almost-was/
r_ =  powmod(r, -1, q)
x = (((s1 * k) - h1) * r_) % q
print("\nx = "+str(x))

# Verify x : we recalculate s1 and s2
k_ = powmod(k, -1, q)
verif_s1 = k_ * (h1 + x*r) % q
print("\ns1 = "+str(s1))
print("   = "+str(verif_s1))
verif_s2 = k_ * (h2 + x*r) % q
print("s2 = "+str(s2))
print("   = "+str(verif_s2))

# Private key reversed, now we will sign our own file
f = open('message.txt', 'rb')
message = f.read()
f.close()

hs = hashlib.sha256(message).hexdigest()
hs = int(hs, 16)

msg_s = k_ * (hs + x*r) % q
print("\nmsg_s = "+str(msg_s))

# save the DER signature file
r_array = int_to_hexarray(r)
s_array = int_to_hexarray(msg_s)

der = [0x30]
der += [2 + len(r_array) + 2 + len(s_array)]
der += [0x02] + [len(r_array)] + r_array
der += [0x02] + [len(s_array)] + s_array
der = bytearray(der)
f = open('message.der', 'wb')
f.write(der)
f.close()

# openssl dgst -sha256 -verify pk.pem -signature message.der message.txt
```

And finally:

```
D:\SecuDay\hard>python resolv.py

r = 15605417920377590881469389245680896390382750610028822061399189974844690419081
  = 15605417920377590881469389245680896390382750610028822061399189974844690419081

x = 27710599426643914408854717972801960575756827944301668676079434617639908625579

s1 = 2503114164189881647415455885730602322305901068129039816129641154861069620595
   = 2503114164189881647415455885730602322305901068129039816129641154861069620595
s2 = 55712711884964560558335380354585001459364905638090643973787639922932968049081
   = 55712711884964560558335380354585001459364905638090643973787639922932968049081

msg_s = 55334051898166299680758219392896539106835523742624946935556046710719151299620
```

Thank you to all the organizers of the SecuDay conference.