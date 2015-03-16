#!/usr/bin/python

#Copyright (C) 2015 - Jos Wetzels.
#See the file 'LICENSE' for copying permission.

"""
Sanity test and example for Flipper
"""

from Crypto.Cipher import AES
from Crypto import Random
from flipper import Flipper

BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def encrypt(plaintext, key):
	iv = Random.new().read(BS)
	aes = AES.new(key, AES.MODE_CBC, iv)
	return iv + aes.encrypt(pad(plaintext))

def decrypt(ciphertext, key):
	iv = ciphertext[:BS]
	ciphertext = ciphertext[BS:]
	aes = AES.new(key, AES.MODE_CBC, iv)
	return unpad(aes.decrypt(ciphertext))

def sanity_check():
	plaintext = Random.new().read(2*BS)
	key = Random.new().read(BS)
	ciphertext = encrypt(plaintext, key)

	flip = Flipper(BS)

	for i in range(0, len(plaintext)):
		flipByte = Random.new().read(1)
		flip.initialize(ciphertext)
		flip.setKnownPlaintext(i, plaintext[i])
		flip.flipPlaintext(i, flipByte)
		mod_ciphertext = flip.finalize()

		mod_plaintext = decrypt(mod_ciphertext, key)	
		
		if(mod_plaintext[i] != flipByte):
			return False

	return True

print "[+]Sane!" if sanity_check() else "[-]Sanity check failed..."