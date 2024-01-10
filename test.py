import base64
import uuid
import secrets
import hashlib

from dto import CompleteClientRegistration
from logging import getLogger
from sys import stdin




# from Crypto.PublicKey import ECC
# from Crypto.Util import number
# from requests import post

# from Crypto.PublicKey import RSA 
import base64
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding 

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dto import (
    ClientRegistrationResponse, CompleteClientRegistration,
    LoginResponse, SystemResponse
)

from dto.ClientRegistrationDetail import ClientRegistrationDetail
from dto.ClientRegistrationDetailEncoder import ClientRegistrationDetailEncoder

from dto.PhoenixResponseCodes import PhoenixResponseCodes

from utils.AuthUtils import AuthUtils
from utils import Constants
from utils.EllipticCurveUtils import EllipticCurveUtils
from utils import HttpUtil
from utils import UtilMethods
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.primitives import serialization, hashes
import json
import binascii

def decrypt_with_private(private_key,input):
    
    
        inputbits =  base64.b64decode(input.encode('UTF-8'))
    
        pkey = serialization.load_pem_private_key(
            private_key.encode('UTF-8'),
            password=None,
            backend=default_backend()
        )
        
        output = pkey.decrypt(
        inputbits,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
   
        return output
    
    
pkey = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDJ3ReBNDKB4JpO
KgGWUn0uQgWbRsYs5wlr5fHD+Z1K02VGh+lKQb4GCC/lb25JCZTVQp5zSGyyBe9e
a+KV1xjwHjq6jwNh8g5tUKLaSCC6fYehfQ7vjc7p2ylhxWBFpHzxwYuTeIgaorMn
mn9gX1TaAx/UajQytu9v3Fc5xvwqMADvcUfEbv/aVzOFsOnA6F8lYLlzw27IcCXB
KZoXb/Td/DDRX6huMi4BEzFNR1p6THhWbxfin48cJbUYN8yTqZvpztgtCYtXKkU7
Xs8b3tzqg7D0Uvq3C1PZEzRYlIDJxQXMaX/XS/c5JmpRQCxjz16zrsa4uuYdKYN
PwohN6kqZAgMBAAECggEAVJZGsSd0OqQpRLOpcpoiRm3393cSt+IgOoxiYKKKXL5
0Y7ez9B/URqbLmzK0Xfqb2TlPODOTCI4gHcrLacp2crfYGDCxVCugDAKMGze6Lyt
G2E6VIaCkoa3qi0Ov8b7ZdFyL5kHNlouy0teUpIeOAMTqY5IVSWMKti74hgdxxyM
SxJaFqooENJhLRoosD/NBbdnlCoHe7stjCnEsvxnge+MywvLxEP+tuuB/DomVmpC
FAVLdhvLrXlnIEgvDY7VMH8xm/4kkFoW+HieBEstg6LVP60Jq1p5W113lPlTXIpC
644UOvCxv/XsJH64S3LhNYqoS4y5ASed9zvjeOp4V2QKBgQD9Dchxe2Vu0HZcVq5
WgVuDAz7FbNbg417asfA18diyFwquDn+72JelHXD3bo0HxFQxlx/s9k6NI7Xf9Oc
bKJCqB8tKZiwl1uxP3H1XDWm0JKip9u6pNadd2p2z5Ydwa+Ra9DZ/wDJX/vK87OF
dngR+HVDxM18mXiN8g6Y+ufgRywKBgQDMNr0LcqwY90RYMSP/h/g8dM5h/DuJBcQ
b2sbZscAOw0E+sNlJacPJd3WcmUXteQpPHrFgQ+IEcDHf8/rTBQi5503JXQpegzo
ExYAi2dJTaSfj89fRE4eFG44peSpbyXka94WEHXvpTO3xfeH7P+sJgHcGtepOOMV
Cmk5kIbY4qwKBgQCSqFBI5LkOliZisaHsZKACt/jDNqb6QwwQNxv+R6HM5Om9oo2
I8qhAe2WjISD/JVueOfW4wa8YwV+A4lCmPsZIpKe/AKQJchwW1LSXpSBj1PMjPg
dnbb8H99F6F0Z9cyovRGXpeBw1P36y255pQVFdPeRRRfKZK+npGetZYzJQLQKBgA
73WAV1wv0VahHYkB3TFjNAEDwII0jYflXYQ8iCiWPLlYWFqncB5FJoidsPNJvByi
qgQjme3/qZSl5yYAiFDu2o8P937SGeFmtxGgHz2sE4LK89GKz+9Gih61pIwfz2GA
UM7OEQ1Br2A142bpBeT9hjbNW2EVToPjSyYFpgSh1/AoGBAIdl1dgG3AofN3ARi9
V3lERIMAFuQnYBTu+qOlMKWXjP7JI7EUVzoYijebQ2BUSM6B964/y1ErVBRO8r3i
btWWpJt/iPlrIpHgGS7pR7u2eCDBLUnDr0MykSWhzgne6Iq9jQXacIaADi0UHcNo
iWnLQaUOK28KhtzXMxPEnA3Vzj
-----END PRIVATE KEY-----"""
authtoken = 'UXynm2jDPAYROBR2XoQcFbUp5kWXutdZBQvkswrnqT+xmkn+j0EHUChy9+I5VSxpJZ0onM5RzB3sQdDcZyjEfxaSMQmVAKtLwbWeeuFGnUj79iHbUjvVjFLJec/V5LPpWkMHfCDxv3QGruVWLtfc/p8iAPatKgWqfIeAz/0O8yfmJNcX8+JOi/lVO04m/lSXBbZ+X4ENZra2FL5JoQj/L5CA0e8BJXD87uwRJhq5E51bR86W/h3vIooAcBlOyCSvapduhEw2kfYJwH0y6q5VFpTOhZ6ZWsBYCEyc2byDuqOeZDyb2Lj8rDxlI2jDUlfvN+SNXN8m+YN2462HKkKtvw=='
temp = decrypt_with_private(pkey,
                            'IWACezKu+RO0Pd3IkMAHgu7xeeVlrwpAOqrrJnXPgQrqhzov857gLGjsXqT58NnKjd+Nt4XkBJmCr0UEc7vBwbULi9loLcA3hQCdsxdEP2qmvvPpoXk0ZmMIFMnOPkU96TOQxN7acQcqu4yrWD5nSMyezvoY+iLSGXmsfL54ugJx7aSheldL7tAb4a0uw4rxqXHmlkEw6ePOd6OT7q1ZBZkmSh09nSFHRrTEJonqnpV5BPo5lS/1d5XSwEBVtKmy4A7ZRKDUw3XqHO1hGbr/hR/6kiS690cHzTWKZkYpDRjasKKMhpzwp2Dxzk30p7uo/vFAYExT/oAM3yp57OC9lQ=='
                     )
print(f'result: {temp}')