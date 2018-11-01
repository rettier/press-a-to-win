import sys

sys.path.insert(0, '../')

from pressa import *

PressA() \
    .setCipher(XORCipher(keylen=29)) \
    .read_base64("./ciphertexts/ntime-pad-29-english-text.b64") \
    .toWin()
