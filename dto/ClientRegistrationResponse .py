import json

class ClientRegistrationResponse:
    def __init__(self):
        self.transactionReference = ""
        self.authToken = ""
        self.serverSessionPublicKey = ""

    def getServerSessionPublicKey(self):
        return self.serverSessionPublicKey

    def setServerSessionPublicKey(self, serverSessionPublicKey):
        self.serverSessionPublicKey = serverSessionPublicKey

    def getTransactionReference(self):
        return self.transactionReference

    def setTransactionReference(self, transactionReference):
        self.transactionReference = transactionReference

    def getAuthToken(self):
        return self.authToken

    def setAuthToken(self, authToken):
        self.authToken = authToken

    def __str__(self):
        return json.dumps(self.__dict__)
