import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEYS_DIRECTORY = 'keys'

def generate_key_pair(username):
    private_key_path = os.path.join(KEYS_DIRECTORY, f'{username}_private_key.pem')
    public_key_path = os.path.join(KEYS_DIRECTORY, f'{username}_public_key.pem')

    # Check if keys already exist
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return

    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save private key
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Get public key
    public_key = private_key.public_key()

    # Save public key
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

if __name__ == "__main__":
    if not os.path.exists(KEYS_DIRECTORY):
        os.makedirs(KEYS_DIRECTORY)

    users = ['user_a', 'user_b']

    for user in users:
        generate_key_pair(user)

    print("Key pairs generated successfully.")
