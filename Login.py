import json
import uuid
import logging
from java.security import KeyPair
from java.util import Map, Scanner
from com.interswitchug.phoenix.simulator.dto import (JSONDataTransform,
    LoginOtpValidationRequest, LoginRequest, LoginResponse, PhoenixResponseCodes,
    SystemResponse)
from com.interswitchug.phoenix.simulator.utils import AuthUtils, Constants, CryptoUtils, EllipticCurveUtils, HttpUtil, UtilMethods

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

base_url = Constants.ROOT_LINK + "client/"
endpoint_url = base_url + "login"
login_endpoint_url = base_url + "validateLoginOtp"

def main():
    curve_utils = EllipticCurveUtils("ECDH")
    pair = curve_utils.generateKeypair()
    private_key = curve_utils.getPrivateKey(pair)
    public_key = curve_utils.getPublicKey(pair)

    terminal_id = Constants.MY_TERMINAL_ID
    response = login(public_key, terminal_id)
    logger.info("LoginResponse : {}", response.getResponseMessage())

    if response.getResponseCode() == PhoenixResponseCodes.APPROVED.CODE and response.getResponse().isRequiresOtp():
        logger.info("Enter received OTP: ")
        otp = input().strip()
        clear_server_session_key = CryptoUtils.decryptWithPrivate(response.getResponse().getServerSessionPublicKey())
        terminal_key = curve_utils.doECDH(private_key, clear_server_session_key)
        otp_response = login_otp(otp, terminal_key)
        logger.info("otpResponse: {}", otp_response)

def login(session_public_key: str, terminal_id: str) -> SystemResponse[LoginResponse]:
    request = LoginRequest()
    request.setTerminalId(terminal_id)
    request.setSerialId(Constants.MY_SERIAL_ID)
    request.setRequestReference(str(uuid.uuid4()))
    request.setAppVersion(Constants.APP_VERSION)

    password_hash = UtilMethods.hash512(Constants.ACCOUNT_PWD) + request.getRequestReference() + Constants.MY_SERIAL_ID
    request.setPassword(CryptoUtils.signWithPrivateKey(password_hash))
    request.setClientSessionPublicKey(session_public_key)

    headers = AuthUtils.generateInterswitchAuth(Constants.POST_REQUEST, endpoint_url, "", "", "")
    json_str = JSONDataTransform.marshall(request)

    response = HttpUtil.postHTTPRequest(endpoint_url, headers, json_str)
    return UtilMethods.unMarshallSystemResponseObject(response, LoginResponse.getClass())

def login_otp(otp: str, terminal_key: str) -> str:
    request = LoginOtpValidationRequest()
    request.setTerminalId(Constants.MY_TERMINAL_ID)
    request.setSerialId(Constants.MY_SERIAL_ID)
    request.setRequestReference(str(uuid.uuid4()))
    request.setAppVersion(Constants.APP_VERSION)
    request.setOtp(CryptoUtils.encrypt(otp, terminal_key))

    headers = AuthUtils.generateInterswitchAuth(Constants.POST_REQUEST, login_endpoint_url, "", "", "", Constants.PRIKEY)
    json_str = JSONDataTransform.marshall(request)

    response = HttpUtil.postHTTPRequest(login_endpoint_url, headers, json_str)
    return response

if __name__ == "__main__":
    main()
