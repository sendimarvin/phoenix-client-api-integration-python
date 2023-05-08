import base64
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import load_pem_private_key

class CryptoUtils:
    
    @staticmethod
    def encrypt(plaintext, terminalKey):
        try:
            iv = get_random_bytes(16)
            key_bytes = base64.b64decode(terminalKey)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception as e:
            print('Exception trace:', e)
            raise SystemApiException(PhoenixResponseCodes.INTERNAL_ERROR.CODE, "Failure to encrypt object")
    
    @staticmethod
    def decrypt(encrypted_value, terminalKey):
        try:
            key_bytes = base64.b64decode(terminalKey)
            iv = encrypted_value[:16]
            ciphertext = encrypted_value[16:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            print('Exception trace:', e)
            raise SystemApiException(PhoenixResponseCodes.INTERNAL_ERROR.CODE, "Failure to decrypt object")
        
    @staticmethod
    def decrypt_with_private(plaintext, private_key):
        try:
            private_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256, mgfunc=lambda x, y: x + y)
            ciphertext = base64.b64decode(plaintext)
            secret = cipher.decrypt(ciphertext)
            return secret.decode('utf-8')
        except Exception as e:
            print('Exception trace:', e)
            raise SystemApiException(PhoenixResponseCodes.INTERNAL_ERROR.CODE, "Failure to decryptWithPrivate ")
    
    @staticmethod
    def encrypt_with_private(plaintext, private_key):
        try:
            private_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256, mgfunc=lambda x, y: x + y)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            print('Exception trace:', e)
            raise SystemApiException(PhoenixResponseCodes.INTERNAL_ERROR.CODE, "Failure to encryptWithPrivate ")
        
    @staticmethod
    def sign_with_private_key(data, private_key):

        # private_key_bytes = private_key.encode('utf-8')
        # key = load_pem_private_key(private_key_bytes, password=None)

        signer = private_key.signer(padding.PKCS1v15(), hashes.SHA256())
        signer.update(data.encode('utf-8'))
        signature = signer.finalize()
        return base64.b64encode(signature).decode('utf-8')
