import json
import uuid
import base64
import requests
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives.asymmetric import rsa



from base64 import b64encode
from base64 import b64decode



from utils import EllipticCurveUtils
from utils.AuthUtils import AuthUtils
from utils import CryptoUtils
from utils import Constants
from utils import UtilMethods 


class KeyExchange:
    endpoint_url = Constants.ROOT_LINK + "client/doKeyExchange"

    @staticmethod
    def do_key_exchange():
        private_key, public_key, private_c_key = KeyExchange.get_curve_key_pair()
        
        req_reference =uuid.uuid4().hex();
        
        print(f"private key: {private_key}")
        
        print(f"private C key: {private_c_key}")
        
          # Generate the RSA private key
        key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
        
        print(f"RSA Priv: {private_c_key}")


        request = {
            "terminalId": Constants.MY_TERMINAL_ID,
            "serialId": Constants.MY_SERIAL_ID,
            "requestReference": req_reference,
            "appVersion": Constants.APP_VERSION,
            "password": KeyExchange.sign_with_private_key(
                b64encode(hashlib.sha512(Constants.ACCOUNT_PWD.strip().encode('UTF-8')).digest()).decode('UTF-8')
                + req_reference + Constants.MY_SERIAL_ID,key
            ),
            "clientSessionPublicKey": public_key,
        }
        
        
        
        print(f"serial id:" + Constants.MY_SERIAL_ID)
        print(f"req_reference: " + req_reference)
        print(f"encrypted password: " + b64encode(hashlib.sha512(Constants.ACCOUNT_PWD.strip().encode('UTF-8')).digest()).decode('UTF-8'))
        print(f"signed password: " +  request["password"])

      

        headers = AuthUtils.generate_interswitch_auth(
            Constants.POST_REQUEST,
            KeyExchange.endpoint_url,
            "",
            "",
            "",
            key
        )

        response = requests.post(KeyExchange.endpoint_url, headers=headers, json=request)
        print(f"response: {response.json()}")
        system_response = UtilMethods.unmarshall_system_response_object(json.dumps(response.json()))
        if system_response.responseCode == PhoenixResponseCodes.APPROVED.CODE:
            clear_server_session_key = CryptoUtils.decrypt_with_private(system_response.response.serverSessionPublicKey)
            terminal_key = EllipticCurveUtils("ECDH").do_ecdh(private_key, clear_server_session_key)
            system_response.response.terminalKey = terminal_key
            if system_response.response.authToken != "":
                system_response.response.authToken = CryptoUtils.decrypt_with_private(system_response.response.authToken)
            return system_response
        else:
            raise SystemApiException(system_response.responseCode, system_response.responseMessage)

    @staticmethod
    def get_curve_key_pair():
    # from cryptography.hazmat.primitives.asymmetric import ec
    # from cryptography.hazmat.primitives import serialization
    # import base64

        # Generate a SECP256R1 private key
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Get the private key's raw components
        private_numbers = private_key.private_numbers()

        # Get the private key's d value (raw scalar value)
        d = private_numbers.private_value

        d_bytes = d.to_bytes((d.bit_length() + 7) // 8, byteorder='big')

        # Get the corresponding public key
        public_key = private_key.public_key()

        # Get the public key's raw components
        public_numbers = public_key.public_numbers()

        # Get the public key's Q value (raw point value)
        Q = public_numbers.public_key().public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

        # Convert the Q value to a byte array
        Q_bytes = Q

        privateCurve =  base64.b64encode(d_bytes).decode("utf-8")
        publicCurve = base64.b64encode(Q_bytes).decode("utf-8")
        privateCKey = private_key

        return privateCurve, publicCurve, private_key
    
    # def decrypt_with_private(private_key,inputbits):
    
    #     pkey = serialization.load_pem_private_key(
    #         private_key.encode('UTF-8'),
    #         password=None,
    #         backend=default_backend()
    #     )
        
    #     output = pkey.decrypt(
    #     inputbits,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #         )
    #     )
   
    #     return output
    
    def sign_with_private_key(data, private_key):
      
            data_bytes = data.encode('utf-8')
            signature = private_key.sign(
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return base64.b64encode(signature).decode('utf-8')
      

class AccountInquiry:
    endpoint_url = Constants.ROOT_LINK + "sente/customerValidation"

    @staticmethod
    def main():
        request = {
            "paymentCode": "53046936951",
            "customerId": Constants.MY_TERMINAL_ID,
            "requestReference": str(uuid.uuid4()),
            "terminalId": Constants.MY_TERMINAL_ID,
            "amount": "600",
            "currencyCode": "800",
        }

        exchange_keys = KeyExchange.do_key_exchange()
        if exchange_keys.responseCode == PhoenixResponseCodes.APPROVED.CODE:
            headers = AuthUtils.generate_interswitch_auth(
                Constants.POST_REQUEST,
                AccountInquiry.endpoint_url,
                "",
                exchange_keys.response.authToken,
                exchange_keys.response.terminalKey,
            )

            response = requests.post(AccountInquiry.endpoint_url, headers=headers, json=request)
            return response.json()
        
    
        
    if __name__ == '__main__':
        main()
