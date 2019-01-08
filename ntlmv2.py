import binascii
import hashlib
import hmac


def gen_NThash(password):

    _ntlm = hashlib.new("md4", password.encode("utf-16-le")).digest()
    ntlm = binascii.hexlify(_ntlm)

    return ntlm

def firstHMAC(username, domain, nthash):

    concat = (username+domain).upper().encode("utf-16-le").hex()
    fhash = hmac.new(binascii.unhexlify(nthash), binascii.unhexlify(concat), hashlib.md5).digest()

    return binascii.hexlify(fhash)
