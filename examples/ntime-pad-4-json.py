import sys

sys.path.insert(0, '../')

from pressa import *

PressA() \
    .setCipher(XORCipher(keylen=4)) \
    .read_binary("./ciphertexts/ntime-pad-4-json.bin") \
    .toWin()
