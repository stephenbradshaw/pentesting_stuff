#!/usr/bin/env python3

# Tidied from https://github.com/tweksteen/jenkins-decrypt and updated for python 3.10
# 
# install pycryptodome for the requirements...

import re
import sys
import base64
from hashlib import sha256
from Crypto.Cipher import AES

MAGIC = b"::::MAGIC::::"

def usage():
    print("./decrypt.py <master.key> <hudson.util.Secret> <credentials.xml|config.xml>")
    sys.exit(0)

def decryptNewPassword(secret, p):
    p = p[1:] #Strip the version

    # Get the length of the IV, almost certainly 16 bytes, but calculating for completeness sake
    iv_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

    # Strip the iv length
    p = p[4:]

    # Get the data length
    data_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)

    # Strip the data length
    p = p[4:]

    iv = p[:iv_length]

    p = p[iv_length:]

    o = AES.new(secret, AES.MODE_CBC, iv)

    decrypted_p = o.decrypt(p)

    # We may need to strip PKCS7 padding
    fully_decrypted_blocks = decrypted_p[:-16]
    possibly_padded_block = decrypted_p[-16:]
    padding_length = possibly_padded_block[-1]
    if padding_length <= 16: # Less than size of one block, so we have padding
        possibly_padded_block = possibly_padded_block[:-padding_length]

    pw = fully_decrypted_blocks + possibly_padded_block
    pw = pw.decode('utf-8')
    return pw

  
def decryptOldPassword(secret, p):
    # Copying the old code, I have not verified if it works
    o = AES.new(secret, AES.MODE_ECB)
    x = o.decrypt(p)
    assert MAGIC in x
    return re.findall('(.*)' + MAGIC, x)[0]


def get_hudson_secret(master_key_file, hudson_key_file):
    master_key = open(master_key_file, 'rb').read()
    hudson_secret_key = open(hudson_key_file, 'rb').read()
    hashed_master_key = sha256(master_key).digest()[:16]
    o = AES.new(hashed_master_key, AES.MODE_ECB)
    secret = o.decrypt(hudson_secret_key)

    #secret = secret[:-16]
    secret = secret[:16]
    return secret



def main():
    if len(sys.argv) != 4:
        usage()

    secret = get_hudson_secret(sys.argv[1], sys.argv[2])
    credentials = open(sys.argv[3]).read()
    passwords = re.findall(r'<(?:password|privateKey|bindPassword)>\{?(.*?)\}?</(?:password|privateKey|bindPassword)>', credentials)

    # You can find the password format at https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/hudson/util/Secret.java#L167-L216

    for password in passwords:
        print('Found a credential and attempting decryption...')
        #p = base64.decodestring(bytes(password, 'utf-8'))
        p = base64.b64decode(bytes(password, 'utf-8'))

        # Get payload version
        payload_version = p[0]
        if payload_version == 1:
            print(decryptNewPassword(secret, p))
        else: # Assuming we don't have a V2 payload, seeing as current crypto isn't horrible that's a fair assumption
            print(decryptOldPassword(secret,p))

if __name__ == '__main__':
    main()
