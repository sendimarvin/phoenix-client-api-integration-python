class ClientTerminalRequest:
    def __init__(self):
        self.terminalId = ""
        self.appVersion = ""
        self.serialId = ""
        self.requestReference = ""
        self.gprsCoordinate = ""

    def getGprsCoordinate(self):
        return self.gprsCoordinate

    def setGprsCoordinate(self, gprsCoordinate):
        self.gprsCoordinate = gprsCoordinate

    def getTerminalId(self):
        return self.terminalId

    def setTerminalId(self, terminalId):
        self.terminalId = terminalId

    def getAppVersion(self):
        return self.appVersion

    def setAppVersion(self, appVersion):
        self.appVersion = appVersion

    def getSerialId(self):
        return self.serialId

    def setSerialId(self, serialId):
        self.serialId = serialId

    def getRequestReference(self):
        return self.requestReference

    def setRequestReference(self, requestReference):
        self.requestReference = requestReference
