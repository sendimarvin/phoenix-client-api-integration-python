import json

class JSONDataTransform:
    
    @staticmethod
    def marshall(object):
        return json.dumps(object, default=lambda o: o.__dict__, sort_keys=True, indent=4)
    
    @staticmethod
    def unmarshall(json_str, object_class):
        return json.loads(json_str, object_hook=lambda d: object_class(**d))
    
    @staticmethod
    def unmarshall_list(json_str, object_class):
        return [JSONDataTransform.unmarshall(item, object_class) for item in json.loads(json_str)]
