from dto.ClientTerminalRequest import ClientTerminalRequest
from typing import Optional
import json

class ClientRegistrationDetail(ClientTerminalRequest, json.JSONEncoder):
    def __init__(
        self, 
        name: Optional[str] = None, 
        phone_number: Optional[str] = None, 
        nin: Optional[str] = None, 
        gender: Optional[str] = None, 
        email_address: Optional[str] = None, 
        owner_phone_number: Optional[str] = None, 
        public_key: Optional[str] = None, 
        client_session_public_key: Optional[str] = None
    ):
        super().__init__()
        self.name = name
        self.phone_number = phone_number
        self.nin = nin
        self.gender = gender
        self.email_address = email_address
        self.owner_phone_number = owner_phone_number
        self.public_key = public_key
        self.client_session_public_key = client_session_public_key

    def __str__(self):
        return f"name: {self.name}, phone_number: {self.phone_number}, nin: {self.nin}, gender: {self.gender}, email_address: {self.email_address}, owner_phone_number: {self.owner_phone_number}, public_key: {self.public_key}, client_session_public_key: {self.client_session_public_key}"
        
    @property
    def client_session_public_key(self) -> Optional[str]:
        return self._client_session_public_key
    
    @client_session_public_key.setter
    def client_session_public_key(self, value: Optional[str]):
        self._client_session_public_key = value
        
    @property
    def name(self) -> Optional[str]:
        return self._name
    
    @name.setter
    def name(self, value: Optional[str]):
        self._name = value
        
    @property
    def phone_number(self) -> Optional[str]:
        return self._phone_number
    
    @phone_number.setter
    def phone_number(self, value: Optional[str]):
        self._phone_number = value
        
    @property
    def nin(self) -> Optional[str]:
        return self._nin
    
    @nin.setter
    def nin(self, value: Optional[str]):
        self._nin = value
        
    @property
    def gender(self) -> Optional[str]:
        return self._gender
    
    @gender.setter
    def gender(self, value: Optional[str]):
        self._gender = value
        
    @property
    def email_address(self) -> Optional[str]:
        return self._email_address
    
    @email_address.setter
    def email_address(self, value: Optional[str]):
        self._email_address = value
        
    @property
    def owner_phone_number(self) -> Optional[str]:
        return self._owner_phone_number
    
    @owner_phone_number.setter
    def owner_phone_number(self, value: Optional[str]):
        self._owner_phone_number = value
        
    @property
    def public_key(self) -> Optional[str]:
        return self._public_key
    
    @public_key.setter
    def public_key(self, value: Optional[str]):
        self._public_key = value


# class ClientRegistrationDetail():