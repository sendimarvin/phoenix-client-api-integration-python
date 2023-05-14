import base64
import uuid
from logging import getLogger
from sys import stdin

from Crypto.PublicKey import ECC
from Crypto.Util import number
from requests import post

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

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

    if registration_response['responseCode'] != PhoenixResponseCodes.APPROVED.value[2]:
        logger.info(
            f"Client Registration failed: {registration_response['responseMessage']}"
        )
    else:
        decrypted_session_key = CryptoUtils.decrypt_with_private(
            registration_response['response']['server_session_public_key'], private_key
        )
        terminal_key = curve_utils.do_ecdh(curve_private_key, decrypted_session_key)
        logger.info("==============terminalKey==============")
        logger.info(f"terminalKey: {terminal_key}")
        auth_token = CryptoUtils.decrypt_with_private(
            registration_response['response']['authToken'], private_key
        )
        transaction_reference = registration_response['response']['transactionReference']
        logger.info("Enter received OTP: ")
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
                logger.info(f"clientSecret: {client_secret}")
        else:
            logger.info(f"finalResponse: {response['responseMessage']}")

def client_registration_request(publicKey, clientSessionPublicKey, privateKey):
    setup = ClientRegistrationDetail()
    setup.setSerialId(Constants.MY_SERIAL_ID)
    setup.name = "API Client"
    setup.nin = "123456"
    setup.owner_phone_number = "0702544870"
    setup.phone_number = "0702544870"
    setup.public_key = publicKey
    setup.requestReference = str(uuid.uuid4())
    setup.terminalId = (Constants.TERMINAL_ID)
    setup.gprsCoordinate = ""
    setup.client_session_public_key = clientSessionPublicKey

    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, REGISTRATION_ENDPOINT_URL, "", "", "", privateKey)


    print("\n\n\n\n"+str(setup)+"\n\n\n\n")

    mjson = json.dumps(setup, cls=ClientRegistrationDetailEncoder) ##client_session_public_key

    return HttpUtil.post_http_request(REGISTRATION_ENDPOINT_URL, headers, mjson)

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
