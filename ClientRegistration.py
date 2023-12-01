import base64
import uuid
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

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
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
from cryptography.hazmat.primitives import serialization, hashes
import json


logger = getLogger("ClientRegistration")

BASE_URL = Constants.ROOT_LINK + "client/"
REGISTRATION_ENDPOINT_URL = BASE_URL + "clientRegistration"
REGISTRATION_COMPLETION_ENDPOINT_URL = BASE_URL + "completeClientRegistration"


def main():
    # Generate key pair

    # Generate the RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    mpublic_key = key.public_key()

    private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

    public_key = mpublic_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    print(f"\n\nprivate key {private_key}\n\n")
    print(f"\n\npublic key {public_key}\n\n")

    curve_private_key, curve_public_key = get_curve_key_pair()

    response = client_registration_request(public_key, curve_public_key, key) #private_key

    print(f"\n\n\nRemote Response: {response}\n\n\n")

    registration_response = json.loads(response)

    if registration_response['responseCode'] != PhoenixResponseCodes.APPROVED.value[0]:
        print(
            f"Client Registration failed: {registration_response['responseMessage']}"
        )
    else:
        
        pkey = serialization.load_pem_private_key(
            private_key.encode('UTF-8'),
            password=None,
            backend=default_backend()
        )
        
        decrypted_session_key = pkey.decrypt(
        base64.b64decode(registration_response['response']['serverSessionPublicKey'].encode('UTF-8')),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        
       
        #terminal_key = do_ecdh(, decrypted_session_key)
        
        
        new_curve_private = curve_private_key.encode('UTF-8')
        new_curve_public = decrypted_session_key
        
        
        #start
        print(f"length of private: " + str(len(decrypted_session_key)))
        print(f"length of public: " + str(len(new_curve_public)))
        
        init = ec.derive_private_key(
            int.from_bytes(new_curve_private, byteorder='big'),
            ec.SECP256R1(),  # You may need to adjust the curve based on your requirements
            default_backend()
        )
        
        doPhase = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),  # You may need to adjust the curve based on your requirements
            base64.b64decode(new_curve_public)
            )
        
       
        peer2_private_key = ec.generate_private_key(
            ec.SECP256R1()
        )
        peer_private_key = ec.generate_private_key(
            ec.SECP256R1()
        )

        
        shared_key = init.exchange(ECDH(), doPhase)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # You may adjust the length based on your requirements
            salt=None,
            info=b'ECDH Key Derivation',
            backend=default_backend()
        ).derive(shared_key)
        
        print(f"base64.b64encode(derived_key).decode('utf-8')")
        
        
        #end
        
        
        print("==============terminalKey==============")
        
        print(f"terminalKey: {terminal_key}")
        
        auth_token = CryptoUtils.decrypt_with_private(
            registration_response['response']['authToken'], private_key
        )
        
        transaction_reference = registration_response['response']['transactionReference']
        
        print("Enter received OTP: ")
        
        otp = stdin.readline().strip()
        
        final_response = complete_registration(
            terminal_key, auth_token, transaction_reference, otp, private_key
        )

        response = json.loads(final_response)
        
        if response['responseCode'] == PhoenixResponseCodes.APPROVED.value[2]:
            client_secret = CryptoUtils.decrypt_with_private(
                response['response']['clientSecret'], private_key
            )
            if client_secret and len(client_secret) > 5:
                print(f"clientSecret: {client_secret}")
        else:
            print(f"finalResponse: {response['responseMessage']}")

def client_registration_request(publicKey, clientSessionPublicKey, privateKey):
    setup = ClientRegistrationDetail()
    setup.setSerialId("0387329999004666")
    setup.name = "pythonclitest"
    setup.nin = "32564365236453"
    setup.owner_phone_number = "0756074321"
    setup.phone_number = "0756074321"
    setup.public_key = publicKey
    setup.requestReference = str(uuid.uuid4())
    setup.terminalId = ("3ISO0511")
    setup.gprsCoordinate = ""
    setup.client_session_public_key = clientSessionPublicKey

    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, REGISTRATION_ENDPOINT_URL, "", "", "", privateKey)


    print("\n\n\n\n"+str(setup)+"\n\n\n\n")

    mjson = json.dumps(setup, cls=ClientRegistrationDetailEncoder) ##client_session_public_key

    return HttpUtil.post_http_request(REGISTRATION_ENDPOINT_URL, headers, mjson)


def do_ecdh(private_key,public_key):
    
    return ""

def complete_registration(terminal_key, auth_token, transaction_reference, otp, private_key):
    complete_reg = CompleteClientRegistration()
    password_hash = UtilMethods.hash512(Constants.ACCOUNT_PWD)
    complete_reg.set_terminal_id(Constants.TERMINAL_ID)
    complete_reg.set_serial_id(Constants.MY_SERIAL_ID)
    complete_reg.set_otp(CryptoUtils.encrypt(otp, terminal_key))
    complete_reg.set_request_reference(str(uuid.uuid4()))
    complete_reg.set_password(CryptoUtils.encrypt(password_hash, terminal_key))
    complete_reg.set_transaction_reference(transaction_reference)
    complete_reg.set_app_version(Constants.APP_VERSION)
    complete_reg.set_gprs_coordinate("")
    
    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, REGISTRATION_COMPLETION_ENDPOINT_URL,
                                                 "", auth_token, terminal_key, private_key)
    json = json.dumps(complete_reg)
    return HttpUtil.post_http_request(REGISTRATION_COMPLETION_ENDPOINT_URL, headers, json)


def get_curve_key_pair():
    # from cryptography.hazmat.primitives.asymmetric import ec
    # from cryptography.hazmat.primitives import serialization
    # import base64

    # Generate a SECP256R1 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Get the private key's raw components
    private_numbers = private_key.private_numbers()

    # Get the private key's d value (raw scalar value)
    d = private_numbers.private_value

    d_bytes = d.to_bytes((d.bit_length() + 7) // 8, byteorder='big')

    # Get the corresponding public key
    public_key = private_key.public_key()

    # Get the public key's raw components
    public_numbers = public_key.public_numbers()

    # Get the public key's Q value (raw point value)
    Q = public_numbers.public_key().public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

    # Convert the Q value to a byte array
    Q_bytes = Q

    privateCurve =  base64.b64encode(d_bytes).decode("utf-8")
    publicCurve = base64.b64encode(Q_bytes).decode("utf-8")

    return privateCurve, publicCurve

if __name__ == '__main__':
    main()
