
import json


class CompleteClientRegistration:
    
    def __init__(self):
        self.otp = None
        self.password = None
        self.transactionReference = None


    def get_password(self):
        return self.password

    def set_password(self, password):
        self.password = password

    def get_transaction_reference(self):
        return self.transactionReference

    def set_transaction_reference(self, transactionReference):
        self.transactionReference = transactionReference
        
    def set_terminal_id(self, terminal_id):
        self.terminalId = terminal_id
    
    def get_terminal_id(self):
        return self.terminalId
    
    def set_serial_id(self, serial_id):
        self.serialId = serial_id
    
    def get_serial_id(self):
        return self.serialId
    
    def set_otp(self, otp):
        self.otp = otp
    
    def get_otp(self):
        return self.otp
    
    def set_request_reference(self, request_reference):
        self.requestReference = request_reference
    
    def get_request_reference(self):
        return self.requestReference
    
    def set_app_version(self, app_version):
        self.appVersion = app_version
    
    def get_app_version(self):
        return self.appVersion
    
    def set_gps_coordinates(self, gps_coordinates):
        self.gpsCoordinates = gps_coordinates
    
    def get_gps_coordinates(self):
        return self.gpsCoordinates
    
    
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

