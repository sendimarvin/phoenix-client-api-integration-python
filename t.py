from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from base64 import b64encode
from cryptography.hazmat.primitives import serialization, hashes

# Generate the RSA private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = key.public_key()

# Encode the keys in base64 format
# Encode the keys in base64 format
private_key_b64 = b64encode(key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)).decode('utf-8')

public_key_b64 = b64encode(public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)).decode('utf-8')

print("\nPrivate key:", private_key_b64)
print("\n\nPublic key:", public_key_b64)

message = b"secret text"
ciphertext = key.public_key().encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# print(ciphertext)



plaintext = key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# print(plaintext)