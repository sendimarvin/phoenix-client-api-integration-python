import base64
import json
import uuid
from logging import getLogger
from sys import stdin

from Crypto.PublicKey import ECC
from Crypto.Util import number
from requests import post

from com.interswitchug.phoenix.simulator.dto import (
    ClientRegistrationDetail, ClientRegistrationResponse, CompleteClientRegistration,
    LoginResponse, PhoenixResponseCodes, SystemResponse
)
from com.interswitchug.phoenix.simulator.utils import AuthUtils, Constants, CryptoUtils, EllipticCurveUtils, HttpUtil, UtilMethods


class ClientRegistration:
    logger = getLogger("ClientRegistration")

    BASE_URL = Constants.ROOT_LINK + "client/"
    REGISTRATION_ENDPOINT_URL = BASE_URL + "clientRegistration"
    REGISTRATION_COMPLETION_ENDPOINT_URL = BASE_URL + "completeClientRegistration"

    @staticmethod
    def main(args):
        pair = ECC.generate(curve='P-256')
        private_key = base64.b64encode(pair.export_key(format='DER')).decode()
        public_key = base64.b64encode(pair.public_key().export_key(format='DER')).decode()

        ClientRegistration.logger.info(f"private key {private_key}")
        ClientRegistration.logger.info(f"public key {public_key}")

        curve_utils = EllipticCurveUtils("ECDH")
        key_pair = curve_utils.generate_key_pair()
        curve_private_key = number.bytes_to_long(key_pair[0]).to_bytes(32, 'big').hex()
        curve_public_key = curve_utils.get_public_key(key_pair)

        response = ClientRegistration.client_registration_request(public_key, curve_public_key, private_key)

        registration_response = UtilMethods.unmarshall_system_response_object(
            response, ClientRegistrationResponse
        )
        if registration_response.response_code != PhoenixResponseCodes.APPROVED.CODE:
            ClientRegistration.logger.info(
                f"Client Registration failed: {registration_response.response_message}"
            )
        else:
            decrypted_session_key = CryptoUtils.decrypt_with_private(
                registration_response.response.server_session_public_key, private_key
            )
            terminal_key = curve_utils.do_ecdh(curve_private_key, decrypted_session_key)
            ClientRegistration.logger.info("==============terminalKey==============")
            ClientRegistration.logger.info(f"terminalKey: {terminal_key}")
            auth_token = CryptoUtils.decrypt_with_private(
                registration_response.response.auth_token, private_key
            )
            transaction_reference = registration_response.response.transaction_reference
            ClientRegistration.logger.info("Enter received OTP: ")
            otp = stdin.readline().strip()
            final_response = ClientRegistration.complete_registration(
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
                    ClientRegistration.logger.info(f"clientSecret: {client_secret}")
            else:
                ClientRegistration.logger.info(f"finalResponse: {response.response_message}")

    @staticmethod
    def client_registration_request(public_key, client_session_public_key, private_key):
        setup = ClientRegistrationDetail()
        setup.serial_id = Constants.MY_SERIAL_ID
        setup.name = "API Client"
        setup.nin = "123456"
        setup.owner_phone_number = "00000"
        setup.phone_number = "00000000"
        setup.public_key = public_key
        setup.request_reference = str(uuid.uuid4())
        setup.terminal_id =
