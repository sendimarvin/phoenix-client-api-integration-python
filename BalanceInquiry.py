import requests
import json
import uuid
from interswitchug.phoenix.simulator.utils import AuthUtils, Constants, HttpUtil
from interswitchug.phoenix.simulator.dto import KeyExchangeResponse, PhoenixResponseCodes, SystemResponse

endpointUrl = Constants.ROOT_LINK + "sente/accountBalance"

def main():
    request = endpointUrl + "?terminalId=" + Constants.MY_TERMINAL_ID + "&requestReference=" + str(uuid.uuid4())

    exchangeKeys = KeyExchange.doKeyExchange()
    if exchangeKeys.getResponseCode() == PhoenixResponseCodes.APPROVED.CODE:
        headers = AuthUtils.generateInterswitchAuth(Constants.GET_REQUEST, request, "",
                                                    exchangeKeys.getResponse().getAuthToken(),
                                                    exchangeKeys.getResponse().getTerminalKey())
        HttpUtil.getHTTPRequest(request, headers)

if __name__ == '__main__':
    main()
