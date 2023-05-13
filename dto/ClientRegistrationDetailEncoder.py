import json
from dto.ClientRegistrationDetail import ClientRegistrationDetail

class ClientRegistrationDetailEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ClientRegistrationDetail):
            return {
                'name': obj.name,
                'nin': obj.nin,
                'phoneNumber': obj.phone_number,
                'clientSessionPublicKey': obj.client_session_public_key,
                'emailAddress': obj.email_address,
                'publicKey': str(obj.public_key),
                'ownerPhoneNumber': obj.owner_phone_number,
                'requestReference': obj.requestReference,
                'serialId': obj.serialId,
                'terminalId': obj.terminalId,
            }
        return json.JSONEncoder.default(self, obj)