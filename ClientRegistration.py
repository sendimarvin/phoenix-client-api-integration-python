import base64
import uuid
from logging import getLogger
from sys import stdin

from Crypto.PublicKey import ECC
from Crypto.Util import number
from requests import post

from dto import (
    ClientRegistrationDetail, ClientRegistrationResponse, CompleteClientRegistration,
    LoginResponse, PhoenixResponseCodes, SystemResponse
)
from utils import AuthUtils, Constants, CryptoUtils, EllipticCurveUtils, HttpUtil, UtilMethods


logger = getLogger("ClientRegistration")

BASE_URL = Constants.ROOT_LINK + "client/"
REGISTRATION_ENDPOINT_URL = BASE_URL + "clientRegistration"
REGISTRATION_COMPLETION_ENDPOINT_URL = BASE_URL + "completeClientRegistration"

def main():
    pair = ECC.generate(curve='P-256')
    private_key = base64.b64encode(pair.export_key(format='DER')).decode()
    public_key = base64.b64encode(pair.public_key().export_key(format='DER')).decode()

    logger.info(f"private key {private_key}")
    logger.info(f"public key {public_key}")

    curve_utils = EllipticCurveUtils("ECDH")
    key_pair = curve_utils.generate_key_pair()
    curve_private_key = number.bytes_to_long(key_pair[0]).to_bytes(32, 'big').hex()
    curve_public_key = curve_utils.get_public_key(key_pair)

    response = client_registration_request(public_key, curve_public_key, private_key)

    registration_response = UtilMethods.unmarshall_system_response_object(
        response, ClientRegistrationResponse
    )
    if registration_response.response_code != PhoenixResponseCodes.APPROVED.CODE:
        logger.info(
            f"Client Registration failed: {registration_response.response_message}"
        )
    else:
        decrypted_session_key = CryptoUtils.decrypt_with_private(
            registration_response.response.server_session_public_key, private_key
        )
        terminal_key = curve_utils.do_ecdh(curve_private_key, decrypted_session_key)
        logger.info("==============terminalKey==============")
        logger.info(f"terminalKey: {terminal_key}")
        auth_token = CryptoUtils.decrypt_with_private(
            registration_response.response.auth_token, private_key
        )
        transaction_reference = registration_response.response.transaction_reference
        logger.info("Enter received OTP: ")
        otp = stdin.readline().strip()
        final_response = complete_registration(
            terminal_key, auth_token, transaction_reference, otp, private_key
        )

        response = UtilMethods.unmarshall_system_response_object(
            final_response, LoginResponse
        )
        if response.response_code == PhoenixResponseCodes.APPROVED.CODE:
            client_secret = CryptoUtils.decrypt_with_private(
                response.response.client_secret, private_key
            )
            if client_secret and len(client_secret) > 5:
                logger.info(f"clientSecret: {client_secret}")
        else:
            logger.info(f"finalResponse: {response.response_message}")

def client_registration_request(publicKey, clientSessionPublicKey, privateKey):
    setup = ClientRegistrationDetail()
    setup.setSerialId(Constants.MY_SERIAL_ID)
    setup.setName("API Client")
    setup.setNin("123456")
    setup.setOwnerPhoneNumber("00000")
    setup.setPhoneNumber("00000000")
    setup.setPublicKey(publicKey)
    setup.setRequestReference(str(UUID.randomUUID()))
    setup.setTerminalId(Constants.TERMINAL_ID)
    setup.setGprsCoordinate("")
    setup.setClientSessionPublicKey(clientSessionPublicKey)

    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, REGISTRATION_ENDPOINT_URL, "", "", "", privateKey)
    json = json.dumps(setup)

    return HttpUtil.postHTTPRequest(REGISTRATION_ENDPOINT_URL, headers, json)

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


if __name__ == '__main__':
    main()
