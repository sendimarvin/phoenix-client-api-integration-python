import base64
import hashlib
import os
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class EllipticCurveUtils:
    
    ELIPTIC_CURVE_PRIME256 = "prime256v1"

    def __init__(self, protocol):
        self.protocol = protocol
    
    def load_public_key(self, data):
        curve = ECC.curvesbyname[self.ELIPTIC_CURVE_PRIME256]
        key = ECC.EllipticCurvePublicNumbers.from_encoded_point(curve, data).public_key()
        return key
    
    def load_private_key(self, data):
        curve = ECC.curvesbyname[self.ELIPTIC_CURVE_PRIME256]
        key = ECC.EllipticCurvePrivateNumbers(int.from_bytes(data, byteorder='big'), ECC.EllipticCurvePublicNumbers.from_encoded_point(curve, curve.generator * int.from_bytes(data, byteorder='big')).private_key()).private_key()
        return key
    
    @staticmethod
    def save_private_key(key):
        return key.d.to_bytes((key.curve.key_size + 7) // 8, byteorder='big')
    
    @staticmethod
    def save_public_key(key):
        return key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
    
    def get_signature(self, plaintext, private_key):
        h = SHA256.new(plaintext.encode())
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(h)
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, signature, plaintext, public_key):
        h = SHA256.new(plaintext.encode())
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            signature = base64.b64decode(signature.encode('utf-8'))
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def do_ecdh(self, private_key, public_key):
        private_key = self.load_private_key(base64.b64decode(private_key))
        public_key = self.load_public_key(base64.b64decode(public_key))
        shared_key = private_key.exchange(public_key)
        return base64.b64encode(shared_key).decode('utf-8')
    
    def generate_key_pair(self):
        key = ECC.generate(curve=self.ELIPTIC_CURVE_PRIME256)
        return key.public_key(), key.export_key(format='PEM')

    def get_private_key(self, key_pair):
        return base64.b64encode(key_pair.export_key(format='PEM', pkcs8=True, passphrase=None)).decode('utf-8')

    def get_public_key(self, key_pair):
        return base64.b64encode(key_pair.public_key().public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)).decode('utf-8')
