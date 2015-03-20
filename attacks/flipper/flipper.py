#!/usr/bin/python

#Copyright (C) 2015 - Jos Wetzels
#See the file 'LICENSE' for copying permission.

"""
Flipper is a simple python class for aiding in exploitation of bitflipping attacks against blockciphers in CBC, OFB and CTR mode.

Given any ciphertext, encrypted under CBC, OFB or CTR mode, we can flip arbitrary bits for which we have corresponding known plaintext.
See: http://en.wikipedia.org/wiki/Bit-flipping_attack and http://cryptopals.com/sets/2/challenges/16/ for more details.

Flipper is used as follows (see sanity.py for example usage) to set bytes from offset {flip_offset} to {flip_target} in the
decrypted plaintext of mod_ciphertext:

	flip = Flipper(blocksize, mode)
	flip.initialize(iv+ciphertext)
	flip.setKnownPlaintext(known_offset, known_plaintext)
	flip.flipPlaintext(flip_offset, flip_target)
	mod_ciphertext = flip.finalize()

"""

class Flipper:
	def __init__(self, blocksize, mode):
		self.bs = blocksize
		self.mode = mode
		return

	def initialize(self, ciphertext):
		self.setIV(ciphertext[:self.bs])
		self.setCiphertext(ciphertext[self.bs:])
		self.kp = [None]*self.e_len
		return

	def finalize(self):
		return self.getIV() + self.getCiphertext()

	def setIV(self, iv):
		self.iv = iv
		return

	def getIV(self):
		return self.iv

	def setCiphertext(self, ciphertext):
		self.e = ciphertext
		self.e_len = len(ciphertext)
		return

	def getCiphertext(self):
		return self.e

	def setKnownPlaintext(self, offset, known):
		if((offset+len(known)) > self.e_len):
			return False

		for i in range(0, len(known)):
			self.kp[offset+i] = known[i]
		return True

	def flipPlaintext_CBC(self, pos, targetStr):
		if((pos+len(targetStr)) > self.e_len):
			return False			

		if(None in self.kp[pos: pos+len(targetStr)]):
			# We have no full known plaintext for this range
			return False

		for i in range(pos, pos+len(targetStr)):
			if(i < self.bs):
				# Corrupt IV			
				iv2 = list(self.iv)
				iv2[i] = chr(ord(self.kp[i]) ^ ord(iv2[i]) ^ ord(targetStr[i-pos]))
				self.iv = "".join(iv2)
			else:
				# Corrupt preceding block (corresponding plaintext block will be garbled)
				e2 = list(self.e)
				e2[i-self.bs] = chr(ord(self.kp[i]) ^ ord(e2[i-self.bs]) ^ ord(targetStr[i-pos]))
				self.e = "".join(e2)
		return True

	def flipPlaintext_OFB_CTR(self, pos, targetStr):
		if((pos+len(targetStr)) > self.e_len):
			return False			

		if(None in self.kp[pos: pos+len(targetStr)]):
			# We have no full known plaintext for this range
			return False

		for i in range(pos, pos+len(targetStr)):
			# Corrupt current byte
			e2 = list(self.e)
			e2[i] = chr(ord(self.kp[i]) ^ ord(e2[i]) ^ ord(targetStr[i-pos]))
			self.e = "".join(e2)
		return True

	def flipPlaintext(self, pos, targetStr):
		modes = {"CBC": self.flipPlaintext_CBC,
				 "OFB": self.flipPlaintext_OFB_CTR,
				 "CTR": self.flipPlaintext_OFB_CTR}

		return modes[self.mode](pos, targetStr)