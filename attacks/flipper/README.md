# Flipper

>Copyright (C) 2015 - Jos Wetzels.
>
>See the file 'LICENSE' for copying permission.

Flipper is a simple python class for aiding in exploitation of bitflipping attacks against blockciphers in CBC, OFB and CTR mode.
Given any ciphertext, encrypted under CBC, OFB or CTR mode, we can flip arbitrary bits for which we have corresponding known plaintext.
See: http://en.wikipedia.org/wiki/Bit-flipping_attack and http://cryptopals.com/sets/2/challenges/16/ for more details.

Flipper is used as follows (see sanity.py for example usage) to set bytes from offset {flip_offset} to {flip_target} in the
decrypted plaintext of mod_ciphertext:

>```python
>flip = Flipper(blocksize, mode)
>flip.initialize(iv+ciphertext)
>flip.setKnownPlaintext(known_offset, known_plaintext)
>flip.flipPlaintext(flip_offset, flip_target)
>mod_ciphertext = flip.finalize()
>```
