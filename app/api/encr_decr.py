import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import binascii


def format_plaintext(is_admin, password):
    tmp = bytearray(str.encode(password))
    return bytes(bytearray((is_admin).to_bytes(1,"big")) + tmp)

def is_admin_cookie(decrypted_cookie):
    return decrypted_cookie[0] == 1

class Encryption(object):
    def __init__(self, in_key=None):
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)
        if in_key is None:
            self._key = AESGCM.generate_key(bit_length=128)
        else:
            self._key = in_key
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, msg):
        nonce = os.urandom(self._block_size_bytes)
        ct = self._aesgcm.encrypt(nonce, msg, None) + nonce
        return ct
    
    def decrypt(self, ctx):
        nonce = ctx[:self._block_size_bytes]
        ct = ctx[self._block_size_bytes:]
        msg = self._aesgcm.decrypt(nonce, ct, None)
        return msg
    

        
if __name__=='__main__':
    test_encr_decr()
