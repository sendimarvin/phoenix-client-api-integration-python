from dto import JSONDataTransform, KeyExchangeResponse, PaymentRequest, PhoenixResponseCodes, SystemResponse
from utils import AuthUtils, Constants, HttpUtil
import uuid


endpointUrl = Constants.ROOT_LINK + "sente/xpayment"

if __name__ == '__main__':
    request = PaymentRequest()
    request.paymentCode = 53046936951
    request.customerId = ""
    request.requestReference = str(uuid.uuid4())
    request.terminalId = Constants.MY_TERMINAL_ID
    request.amount = 600
    request.currencyCode = "4444"

    additionalData = str(request.amount) + "&" + request.terminalId + "&" + request.requestReference + "&" + request.customerId + "&" + str(request.paymentCode)

    exchangeKeys = KeyExchange.doKeyExchange()

    if exchangeKeys.responseCode == PhoenixResponseCodes.APPROVED.CODE:
        authToken = exchangeKeys.response.authToken
        sessionKey = exchangeKeys.response.terminalKey

        headers = AuthUtils.generateInterswitchAuth(Constants.POST_REQUEST, endpointUrl, additionalData, authToken, sessionKey)

        HttpUtil.postHTTPRequest(endpointUrl, headers, JSONDataTransform.marshall(request))
