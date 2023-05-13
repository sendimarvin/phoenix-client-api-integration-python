import base64
import calendar
import hashlib
import time
import urllib.parse
import uuid

from typing import Dict
from datetime import datetime
from pytz import timezone

from utils.CryptoUtils import CryptoUtils


class AuthUtils:
    @staticmethod
    def generate_interswitch_auth(http_method: str, resource_url: str,
                                  additional_parameters: str, auth_token: str,
                                  terminal_key: str, private_key: str = '') -> Dict[str, str]:
        interswitch_auth = {}

        ug_time_zone = timezone('Africa/Kampala')
        calendar = datetime.now(ug_time_zone)
        timestamp = int(calendar.timestamp())

        uuid_str = str(uuid.uuid4()).replace('-', '')
        nonce = uuid_str

        client_id = 'IKIAE49C7B4ACC0077BD80058314D71A66A7C6FCC286'
        client_secret = 'UtqTs3rO9XUzwKkeoCYKP0CCT9CDGmPePnonViczpWA='

        

        authorization = f'InterswitchAuth {base64.b64encode(client_id.encode()).decode()}'

        encoded_resource_url = urllib.parse.quote(resource_url, safe='')
        signature_cipher = f'{http_method}&{encoded_resource_url}&{timestamp}&{nonce}&{client_id}&{client_secret}'

        if additional_parameters:
            signature_cipher += f'&{additional_parameters}'

        print(f'signature cipher {signature_cipher}')

        #sha512_digest = hashlib.sha512(signature_cipher.encode()).digest()

        if private_key:
            signature = CryptoUtils.sign_with_private_key(signature_cipher, private_key)
        else:
            signature = CryptoUtils.sign_with_private_key(signature_cipher)

        interswitch_auth['Authorization'] = authorization
        interswitch_auth['Timestamp'] = str(timestamp)
        interswitch_auth['Nonce'] = nonce
        interswitch_auth['Signature'] = signature

        if terminal_key:
            auth_token = CryptoUtils.encrypt(auth_token, terminal_key)
        else:
            auth_token = ''

        interswitch_auth['Auth-Token'] = auth_token

        return interswitch_auth
