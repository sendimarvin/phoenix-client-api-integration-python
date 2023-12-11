import json
import uuid

import requests

from utils import EllipticCurveUtils
from utils import AuthUtils
from utils import CryptoUtils
from utils import Constants


class KeyExchange:
    endpoint_url = Constants.ROOT_LINK + "client/doKeyExchange"

    @staticmethod
    def do_key_exchange():
        curve_utils = EllipticCurveUtils("ECDH")
        key_pair = curve_utils.generate_keypair()
        private_key = curve_utils.get_private_key(key_pair)
        public_key = curve_utils.get_public_key(key_pair)

        request = {
            "terminalId": Constants.MY_TERMINAL_ID,
            "serialId": Constants.MY_SERIAL_ID,
            "requestReference": str(uuid.uuid4()),
            "appVersion": Constants.APP_VERSION,
            "password": CryptoUtils.sign_with_private_key(
                UtilMethods.hash_512(Constants.ACCOUNT_PWD) + request["requestReference"] + Constants.MY_SERIAL_ID,
            ),
            "clientSessionPublicKey": public_key,
        }

        headers = AuthUtils.generate_interswitch_auth(
            Constants.POST_REQUEST,
            KeyExchange.endpoint_url,
            "",
            "",
            "",
        )

        response = requests.post(KeyExchange.endpoint_url, headers=headers, json=request)
        system_response = UtilMethods.unmarshall_system_response_object(response.json(), KeyExchangeResponse)
        if system_response.responseCode == PhoenixResponseCodes.APPROVED.CODE:
            clear_server_session_key = CryptoUtils.decrypt_with_private(system_response.response.serverSessionPublicKey)
            terminal_key = EllipticCurveUtils("ECDH").do_ecdh(private_key, clear_server_session_key)
            system_response.response.terminalKey = terminal_key
            if system_response.response.authToken != "":
                system_response.response.authToken = CryptoUtils.decrypt_with_private(system_response.response.authToken)
            return system_response
        else:
            raise SystemApiException(system_response.responseCode, system_response.responseMessage)


class AccountInquiry:
    endpoint_url = Constants.ROOT_LINK + "sente/customerValidation"

    @staticmethod
    def main():
        request = {
            "paymentCode": "53046936951",
            "customerId": Constants.MY_TERMINAL_ID,
            "requestReference": str(uuid.uuid4()),
            "terminalId": Constants.MY_TERMINAL_ID,
            "amount": "600",
            "currencyCode": "800",
        }

        exchange_keys = KeyExchange.do_key_exchange()
        if exchange_keys.responseCode == PhoenixResponseCodes.APPROVED.CODE:
            headers = AuthUtils.generate_interswitch_auth(
                Constants.POST_REQUEST,
                AccountInquiry.endpoint_url,
                "",
                exchange_keys.response.authToken,
                exchange_keys.response.terminalKey,
            )

            response = requests.post(AccountInquiry.endpoint_url, headers=headers, json=request)
            return response.json()
