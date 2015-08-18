import binascii
import hashlib
import argparse
import os


parser = argparse.ArgumentParser(description="Generate a password hash and accompaning salt")
parser.add_argument('password')
args = parser.parse_args()

salt = os.urandom(32)
print(binascii.hexlify(salt))
pass_hash = hashlib.pbkdf2_hmac('sha256', bytearray(args.password, 'UTF-8'), salt, 1000)
print(binascii.hexlify(pass_hash))
