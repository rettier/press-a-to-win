import sys

sys.path.insert(0, '../')

from pressa import *


class ModVigenere(Cipher):
    def encrypt_char(self, plaintext, pos, key):
        mode = (pos % 13) % 8
        if mode in [0, 2, 4, 5]:
            return plaintext[pos] ^ key[pos % self.keylen]
        elif mode in [1, 6]:
            return (plaintext[pos] + key[pos % self.keylen]) % 256
        elif mode in [3, 7]:
            return (plaintext[pos] - key[pos % self.keylen]) % 256
        else:
            assert False

    def decrypt_char(self, cipher, pos, key):
        mode = (pos % 13) % 8
        if mode in [0, 2, 4, 5]:
            return cipher[pos] ^ key[pos % self.keylen]
        elif mode in [1, 6]:
            return (cipher[pos] - key[pos % self.keylen]) % 256
        elif mode in [3, 7]:
            return (cipher[pos] + key[pos % self.keylen]) % 256
        else:
            assert False


PressA() \
    .setCipher(ModVigenere(keylen=13)) \
    .read_hex("./ciphertexts/mod-vigenere-8.hex") \
    .toWin()
