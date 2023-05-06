import json
import uuid
import requests
from Crypto.PublicKey import ECC
from dto import KeyExchangeRequest, KeyExchangeResponse
from utils import AuthUtils, Constants, CryptoUtils, EllipticCurveUtils, HttpUtil, UtilMethods

endpoint_url = Constants.ROOT_LINK + "client/doKeyExchange"

def do_key_exchange():
    curve_utils = EllipticCurveUtils("ECDH")
    pair = curve_utils.generate_keypair()
    private_key = curve_utils.get_private_key(pair)
    public_key = curve_utils.get_public_key(pair)

    request = KeyExchangeRequest()
    request.terminal_id = Constants.MY_TERMINAL_ID
    request.serial_id = Constants.MY_SERIAL_ID
    request.request_reference = uuid.uuid4().hex
    request.app_version = Constants.APP_VERSION
    password_hash = UtilMethods.hash_512(Constants.ACCOUNT_PWD) + request.request_reference + Constants.MY_SERIAL_ID
    request.password = CryptoUtils.sign_with_private_key(password_hash)
    request.client_session_public_key = public_key

    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, endpoint_url, "", "", "")
    json_data = json.dumps(request.__dict__)

    response = HttpUtil.post_http_request(endpoint_url, headers, json_data)
    keyxchange_response = UtilMethods.unmarshall_system_response_object(response, KeyExchangeResponse)
    if keyxchange_response.response_code == "00":
        clear_server_session_key = CryptoUtils.decrypt_with_private_key(keyxchange_response.response.server_session_public_key)
        terminal_key = EllipticCurveUtils("ECDH").do_ecdh(private_key, clear_server_session_key)
        keyxchange_response.response.terminal_key = terminal_key
        if keyxchange_response.response.auth_token:
            keyxchange_response.response.auth_token = CryptoUtils.decrypt_with_private_key(keyxchange_response.response.auth_token)
        return keyxchange_response
    else:
        raise ValueError(keyxchange_response.response_code, keyxchange_response.response_message)
