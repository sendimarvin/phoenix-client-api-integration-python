class CompleteClientRegistration(ClientTerminalRequest):
    def __init__(self):
        self.otp = None
        self.password = None
        self.transactionReference = None

    def getOtp(self):
        return self.otp

    def setOtp(self, otp):
        self.otp = otp

    def getPassword(self):
        return self.password

    def setPassword(self, password):
        self.password = password

    def getTransactionReference(self):
        return self.transactionReference

    def setTransactionReference(self, transactionReference):
        self.transactionReference = transactionReference