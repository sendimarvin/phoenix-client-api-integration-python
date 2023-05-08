import json
from dto.ClientRegistrationDetail import ClientRegistrationDetail

class ClientRegistrationDetailEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ClientRegistrationDetail):
            return {
                'name': obj.name,
                'nin': obj.nin,
                'phone_number': obj.phone_number
            }
        return json.JSONEncoder.default(self, obj)