import requests
import json
import uuid
import KeyExchange
from utils import AuthUtils, Constants, HttpUtil
from dto import KeyExchangeResponse, PhoenixResponseCodes, SystemResponse

endpointUrl = Constants.ROOT_LINK + "sente/accountBalance"

def main():
    request = endpointUrl + "?terminalId=" + Constants.MY_TERMINAL_ID + "&requestReference=" + str(uuid.uuid4())

    exchangeKeys = KeyExchange.do_key_exchange()
    if exchangeKeys.getResponseCode() == PhoenixResponseCodes.APPROVED.CODE:
        headers = AuthUtils.generateInterswitchAuth(Constants.GET_REQUEST, request, "",
                                                    exchangeKeys.getResponse().getAuthToken(),
                                                    exchangeKeys.getResponse().getTerminalKey())
        HttpUtil.get_http_request(request, headers)

if __name__ == '__main__':
    main()
