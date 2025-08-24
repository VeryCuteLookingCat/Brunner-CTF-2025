# Timing Is Everything
This challenge presented you with a 'timing.elf', this elf file prompted you for a 'key'. If you provided the wrong key It would just respond with 'Wrong Key.'
I don't primarily use linux so I did all of the reverse engineering on windows, The first thing I did was I plugged the program into Detect It Easy. Detect it Easy tells you all the characteristics of a program and lets you view the static strings.
![Detect It Easy](https://github.com/VeryCuteLookingCat/Brunner-CTF-2025/blob/main/RE-Timing-Is-Everything/step_1.png)
I saw all of the python declerations and the string 'Py_DecRef' stood out to me. I assumed that this was a python program compiled into an executable. I used a tool called 'pyinstxtractor' (https://github.com/extremecoders-re/pyinstxtractor) to extract out the python bytecode. I was presented with a bunch of files but I could tell 'chall.pyc' was where all of the code was. I used PyLingual(https://pylingual.io/) to get the original python code. What I got was this:
```py

_ = lambda __: __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b32decode(__[::-1])))
exec(_(b'Large encrypted blob'))
```
I immediately assumed that this was it and that the source behind that string, Boy was I wrong. The large encrypted blob decoded into something roughly like this:
```py
exec(_(b'Large encrypted blob'))
```
I thought I had broken something, that I did something wrong, but nope. I kept repeating this cycle of decrypting the blobs of text until I finally noticed change at the 'start' of the blob. I did around 10 times before I gave up and wrote a script to do it:
```py
import dis, Crypto, types
_ = lambda __: __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b32decode(__[::-1])))
co = (_(b'Original large encrypted blob'))
iterationCount = 0
def decompile(code):
	global iterationCount
	load_consts = [i.argval for i in dis.get_instructions(code) if i.opname == "LOAD_CONST"]
	if len(load_consts) == 1:
		iterationCount += 1
		print(iterationCount)

		decompile(_(load_consts[0]))
	else:
		print(dis.dis(code))

decompile(co)
```
I tracked the iterations just for fun and to see how many It would've taken. It was over 60 iterations of just decoding strings before I got python bytecode. The challenge wasn't over yet, because this was the bytecode I got:
```
  0           RESUME                   0

  1           LOAD_NAME                0 (int)
              LOAD_NAME                1 (print)
              LOAD_NAME                2 (str)
              LOAD_NAME                3 (__name__)
              LOAD_NAME                4 (input)
              BUILD_TUPLE              5
              UNPACK_SEQUENCE          5
              STORE_NAME               5 (lllllllllllllll)
              STORE_NAME               6 (llllllllllllllI)
              STORE_NAME               7 (lllllllllllllIl)
              STORE_NAME               8 (lllllllllllllII)
              STORE_NAME               9 (llllllllllllIll)

  3           LOAD_CONST               0 (0)
              LOAD_CONST               1 (('time',))
              IMPORT_NAME             10 (time)
              IMPORT_FROM             10 (time)
              STORE_NAME              11 (lllIlIIlIIIlII)
              POP_TOP

  4           LOAD_CONST               0 (0)
              LOAD_CONST               2 (('md5',))
              IMPORT_NAME             12 (hashlib)
              IMPORT_FROM             13 (md5)
              STORE_NAME              14 (IIIlllIIIIlIIl)
              POP_TOP

  5           LOAD_CONST               0 (0)
              LOAD_CONST               3 (('decompress',))
              IMPORT_NAME             15 (zlib)
              IMPORT_FROM             16 (decompress)
              STORE_NAME              17 (llllllIllIIIll)
              POP_TOP

  6           LOAD_CONST               0 (0)
              LOAD_CONST               4 (('b64decode',))
              IMPORT_NAME             18 (base64)
              IMPORT_FROM             19 (b64decode)
              STORE_NAME              20 (lllllllIIllIlI)
              POP_TOP

  7           LOAD_CONST               0 (0)
              LOAD_CONST               5 (('AES',))
              IMPORT_NAME             21 (Crypto.Cipher)
              IMPORT_FROM             22 (AES)
              STORE_NAME              23 (IIIllllIlIIIll)
              POP_TOP

  8           LOAD_CONST               0 (0)
              LOAD_CONST               6 (('unpad',))
              IMPORT_NAME             24 (Crypto.Util.Padding)
              IMPORT_FROM             25 (unpad)
              STORE_NAME              26 (IlIIlllIlIllIl)
              POP_TOP

 10           LOAD_CONST               7 (<code object IIIIllIIIIlIIIIIII at 0x000002AFBFAE23F0, file "<x>", line 10>)
              MAKE_FUNCTION
              STORE_NAME              27 (IIIIllIIIIlIIIIIII)

 14           LOAD_CONST               8 (<code object lIlIllIlIIIllIllIl at 0x000002AFBFB53630, file "<x>", line 14>)
              MAKE_FUNCTION
              STORE_NAME              28 (lIlIllIlIIIllIllIl)

 19           LOAD_CONST               9 (<code object llIIlIIllIIllIIlII at 0x000002AFBFEA94D0, file "<x>", line 19>)
              MAKE_FUNCTION
              STORE_NAME              29 (llIIlIIllIIllIIlII)

 25           LOAD_NAME                8 (lllllllllllllII)
              LOAD_CONST              10 ('__main__')
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_FALSE        8 (to L1)

 26           LOAD_NAME               29 (llIIlIIllIIllIIlII)
              PUSH_NULL
              CALL                     0
              POP_TOP
              RETURN_CONST            11 (None)

 25   L1:     RETURN_CONST            11 (None)

Disassembly of <code object IIIIllIIIIlIIIIIII at 0x000002AFBFAE23F0, file "<x>", line 10>:
 10           RESUME                   0

 11           LOAD_GLOBAL              1 (lllllllllllllll + NULL)
              LOAD_GLOBAL              3 (lllIlIIlIIIlII + NULL)
              CALL                     0
              CALL                     1
              LOAD_CONST               1 (5)
              BINARY_OP                2 (//)
              STORE_FAST               0 (IIlIlIlIlIIIIIlIlI)

 12           LOAD_GLOBAL              5 (IIIlllIIIIlIIl + NULL)
              LOAD_GLOBAL              7 (lllllllllllllIl + NULL)
              LOAD_FAST                0 (IIlIlIlIlIIIIIlIlI)
              CALL                     1
              LOAD_ATTR                9 (encode + NULL|self)
              CALL                     0
              CALL                     1
              LOAD_ATTR               11 (hexdigest + NULL|self)
              CALL                     0
              LOAD_CONST               0 (None)
              LOAD_CONST               2 (8)
              BINARY_SLICE
              RETURN_VALUE

Disassembly of <code object lIlIllIlIIIllIllIl at 0x000002AFBFB53630, file "<x>", line 14>:
 14           RESUME                   0

 15           LOAD_CONST               1 ('eJwBQAC///INGhHE3NxF/urXW/kJBNU6DwT3T7fUByc61o/eECGpDj1ZkXfolApZ7ZhBLNqcwJ9sT3yGOZau0S0KuG9GrtTx9x8H')
              STORE_FAST               0 (IIIIllIlllIIIIlIlI)

 16           LOAD_CONST               2 (b'\xea\xd1\xf8T\xe9\x86\xe2S\x86Z\xae\x1c\xe4\xd3MT')
              STORE_FAST               1 (IlIllIIlIllIIIlIlI)

 17           LOAD_GLOBAL              1 (IlIIlllIlIllIl + NULL)
              LOAD_GLOBAL              2 (IIIllllIlIIIll)
              LOAD_ATTR                4 (new)
              PUSH_NULL
              LOAD_FAST                1 (IlIllIIlIllIIIlIlI)
              LOAD_GLOBAL              2 (IIIllllIlIIIll)
              LOAD_ATTR                6 (MODE_ECB)
              CALL                     2
              LOAD_ATTR                9 (decrypt + NULL|self)
              LOAD_GLOBAL             11 (llllllIllIIIll + NULL)
              LOAD_GLOBAL             13 (lllllllIIllIlI + NULL)
              LOAD_FAST                0 (IIIIllIlllIIIIlIlI)
              CALL                     1
              CALL                     1
              CALL                     1
              LOAD_GLOBAL              2 (IIIllllIlIIIll)
              LOAD_ATTR               14 (block_size)
              CALL                     2
              LOAD_ATTR               17 (decode + NULL|self)
              CALL                     0
              RETURN_VALUE

Disassembly of <code object llIIlIIllIIllIIlII at 0x000002AFBFEA94D0, file "<x>", line 19>:
 19           RESUME                   0

 20           LOAD_GLOBAL              1 (llllllllllllIll + NULL)
              LOAD_CONST               1 ('Enter the key: ')
              CALL                     1
              LOAD_ATTR                3 (strip + NULL|self)
              CALL                     0
              STORE_FAST               0 (IlIllIIlIllIIIlIlI)

 21           LOAD_FAST                0 (IlIllIIlIllIIIlIlI)
              LOAD_GLOBAL              5 (IIIIllIIIIlIIIIIII + NULL)
              CALL                     0
              COMPARE_OP              88 (bool(==))
              POP_JUMP_IF_FALSE       20 (to L1)

 22           LOAD_GLOBAL              7 (llllllllllllllI + NULL)
              LOAD_GLOBAL              9 (lIlIllIlIIIllIllIl + NULL)
              CALL                     0
              CALL                     1
              POP_TOP
              RETURN_CONST             0 (None)

 24   L1:     LOAD_GLOBAL              7 (llllllllllllllI + NULL)
              LOAD_CONST               2 ('Wrong key.')
              CALL                     1
              POP_TOP
              RETURN_CONST             0 (None)
```
This was better than what I started with but still not the most legible. The important part to me was the encrypted strings inside. I could see that it had to deal with AES and had some kind of string of bytes which I assumed was the key. Now I forgot to mention that with the pyc came a library called "Crpyto" which I didn't pay much attention to. But the bytecode showed it calling functions from Crypto to decrypt what was the alleged flag. I tried to convert as much bytecode as I could to regular python and I roughly got This:
```py
import zlib
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_payload():
    # Encrypted string
    enc_str = 'eJwBQAC///INGhHE3NxF/urXW/kJBNU6DwT3T7fUByc61o/eECGpDj1ZkXfolApZ7ZhBLNqcwJ9sT3yGOZau0S0KuG9GrtTx9x8H'
    key_bytes = b'\xea\xd1\xf8T\xe9\x86\xe2S\x86Z\xae\x1c\xe4\xd3MT'
    
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    encrypted_bytes = b64decode(enc_str)
    encrypted_bytes = zlib.decompress(encrypted_bytes)
    
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    decrypted_bytes = unpad(decrypted_bytes, AES.block_size)
    
    return decrypted_bytes.decode()

print(decrypt_payload())

```
Running this, Finally gave me the flag:
```
brunner{T1m3_1s_4_5tr0nG_k3Y_2_0p3n_53cur3_v4ultz}
```

This was a pretty fun challenge and threw a few curveballs I didn't expect. I wasn't expecting this to be a python program, and I learned some new things about marshal and python! It was a very fun challenge!
