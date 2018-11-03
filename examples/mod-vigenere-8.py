import sys

sys.path.insert(0, '../')

from pressa import *


class ModVigenere(Cipher):
    def encrypt_char(self, plaintext, pos, key):
        mode = (pos % self.keylen) % 8
        if mode in [0, 2, 4, 5]:
            return plaintext[pos] ^ key[pos % self.keylen]
        elif mode in [1, 6]:
            return (plaintext[pos] + key[pos % self.keylen]) % 256
        elif mode in [3, 7]:
            return (plaintext[pos] - key[pos % self.keylen]) % 256
        else:
            assert False

    def decrypt_char(self, cipher, pos, key):
        mode = (pos % self.keylen) % 8
        if mode in [0, 2, 4, 5]:
            return cipher[pos] ^ key[pos % self.keylen]
        elif mode in [1, 6]:
            return (cipher[pos] - key[pos % self.keylen]) % 256
        elif mode in [3, 7]:
            return (cipher[pos] + key[pos % self.keylen]) % 256
        else:
            assert False

    def calculate_key(self, cipher, pos, plaintext):
        res = []
        for i, p in enumerate(plaintext):
            i2 = pos + i
            mode = (i2 % self.keylen) % 8
            if mode in [0, 2, 4, 5]:
                res.append(cipher[i2] ^ plaintext[i % self.keylen])
            elif mode in [1, 6]:
                res.append((cipher[i2] - plaintext[i % self.keylen]) % 256)
            elif mode in [3, 7]:
                res.append(256 - ((cipher[i2] - plaintext[i % self.keylen]) % 256))
            else:
                assert False
        return bytes(res)


PressA() \
    .setCipher(ModVigenere(keylen=13)) \
    .read_hex("./ciphertexts/mod-vigenere-8.hex") \
    .toWin()
