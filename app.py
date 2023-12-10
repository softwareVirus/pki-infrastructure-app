from flask import Flask, render_template, request, flash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "hello_world"
custom_delimiter = b"<DELIMITER>"
username_a = "user_a"
username_b = "user_b"


@app.route("/")
def index():
    return render_template("index.html")


# Helper functions


# get private key of username from pem file
def load_private_key(username):
    private_key_path = f"keys/{username}_private_key.pem"
    with open(private_key_path, "rb") as private_key_file:
        return serialization.load_pem_private_key(
            private_key_file.read(), password=None, backend=default_backend()
        )


# get public key of username from pem file
def load_public_key(username):
    public_key_path = f"keys/{username}_public_key.pem"
    with open(public_key_path, "rb") as public_key_file:
        return serialization.load_pem_public_key(
            public_key_file.read(), backend=default_backend()
        )


# generate symmetric key using PBKDF2-HMAC (Password-Based Key Derivation Function 2 with Hash-based Message Authentication Code)
def generate_symmetric_key():
    salt = os.urandom(16)
    passphrase = b"my_secret_passphrase"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,  # Length in bits
    )

    return kdf.derive(passphrase)


# encrypt text using symmetric key with AES algorithm
def encrypt_symmetric_key(data, symmetric_key):
    cipher = Cipher(
        algorithms.AES(symmetric_key),
        modes.CFB(b"\x00" * 16),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext


# decrypt text using symmetric key with AES algorithm
def decrypt_symmetric_key(ciphertext, symmetric_key):
    cipher = Cipher(
        algorithms.AES(symmetric_key),
        modes.CFB(b"\x00" * 16),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data


# route for User A
@app.route("/user_a", methods=["GET", "POST"])
def user_a():
    result_message = ""
    if request.method == "POST":
        # handle file upload and selected action

        # for simplicity, let's assume the files are stored on the server after processing
        files = request.files.getlist("file")

        uploaded_file = files[0]

        # save file under the uploads directory of project with the same name
        uploaded_file.save(f"uploads/{uploaded_file.filename}")

        """
        encrypt text using symmetric key with AES algorithm

        types: 
            sign file
            encrypt file
            sign and encrypt file
        """
        action = request.form["action"]
        if action == "sign":
            try:
                # get private key of user A
                private_key_a = load_private_key(username_a)
                # read file data from uploads directory
                with open(f"uploads/{uploaded_file.filename}", "rb") as file:
                    data = file.read()
                """
                    sign the data using the private key with PSS(Probabilistic signature scheme) padding and SHA-256 hash.
                    source = https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
                """
                digital_signature = private_key_a.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                # write data of file and digital_signature with inserting custom delimiter to signed directory as adding signed at the beginning of file name
                with open(
                    f"signed/signed_{uploaded_file.filename}", "wb"
                ) as signed_file:
                    signed_file.write(data)
                    signed_file.write(custom_delimiter)  # Add a separator
                    signed_file.write(digital_signature)
                # if process is successfully finished, display information
                result_message += (
                    f"File '{uploaded_file.filename}' signed successfully.<br>"
                )
            except Exception as e:
                # if there is an error, display error information
                result_message += (
                    f"Error signing file '{uploaded_file.filename}': {str(e)}<br>"
                )
        elif action == "encrypt":
            try:
                # get public key of user B
                public_key_b = load_public_key(username_b)
                # generate symmetric key
                symmetric_key = generate_symmetric_key()
                # read file data
                with open(f"uploads/{uploaded_file.filename}", "rb") as file:
                    data = file.read()

                # encrypt file data with AES algorithm using symmetric key thanks to encrypt_symmetric_key i created as custom function
                ciphertext = encrypt_symmetric_key(data, symmetric_key)

                """
                Use the OAEP(Optimal asymmetric encryption padding) padding scheme with SHA-256 as the hash function for added security                
                source: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
                """
                encrypted_symmetric_key = public_key_b.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # save encrypted symmetric key and ciphertext with custom_delimiter to encypted directory as adding encypted at the beginning of file name
                with open(
                    f"encrypted/encrypted_{uploaded_file.filename}", "wb"
                ) as encrypted_file:
                    encrypted_file.write(encrypted_symmetric_key)
                    encrypted_file.write(custom_delimiter)  # Add a separator
                    encrypted_file.write(ciphertext)

                # if process is successfully finished, display information
                result_message += (
                    f"File '{uploaded_file.filename}' encrypted successfully.<br>"
                )
            except Exception as e:
                # if there is an error, display error information
                result_message += (
                    f"Error encrypting file '{uploaded_file.filename}': {str(e)}<br>"
                )
        elif action == "sign_and_encrypt":
            try:
                # get private key of user A
                private_key_a = load_private_key(username_a)
                # get public key of user B
                public_key_b = load_public_key(username_b)
                # generate symmetric key
                symmetric_key = generate_symmetric_key()

                # read file data
                with open(f"uploads/{uploaded_file.filename}", "rb") as file:
                    data = file.read()

                """
                    sign the data using the private key with PSS(Probabilistic signature scheme) padding and SHA-256 hash.
                    source = https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
                """
                signature = private_key_a.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                # encrypt file data with AES algorithm using symmetric key thanks to encrypt_symmetric_key i created as custom function
                ciphertext = encrypt_symmetric_key(data, symmetric_key)

                """
                Use the OAEP(Optimal asymmetric encryption padding) padding scheme with SHA-256 as the hash function for added security                
                source: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
                """
                encrypted_symmetric_key = public_key_b.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                """
                save encrypted symmetric key, ciphertext, and signature with custom_delimiter to signed_and_encypted directory as 
                adding signed_and_encypted at the beginning of file name
                """
                with open(
                    f"signed_and_encrypted/signed_and_encrypted_{uploaded_file.filename}",
                    "wb",
                ) as signed_encrypted_file:
                    signed_encrypted_file.write(encrypted_symmetric_key)
                    signed_encrypted_file.write(custom_delimiter)  # Add a separator
                    signed_encrypted_file.write(ciphertext)
                    signed_encrypted_file.write(custom_delimiter)  # Add a separator
                    signed_encrypted_file.write(signature)

                # if process is successfully finished, display information
                result_message += f"File '{uploaded_file.filename}' signed and encrypted successfully.<br>"
            except Exception as e:
                # if there is an error, display error information
                result_message += f"Error signing and encrypting file '{uploaded_file.filename}': {str(e)}<br>"
    flash(result_message)

    # render jinja2 template using render_template function to show user A as interface
    return render_template("user_a.html")


# route for User B
@app.route("/user_b", methods=["GET", "POST"])
def user_b():
    if request.method == "POST":
        # handle file upload and selected action
        uploaded_file = request.files["file"]

        # save file under the uploads directory of project with the same name
        uploaded_file.save(f"uploads/{uploaded_file.filename}")

        action = request.form["action"]
        result_message = ""

        """
        encrypt text using symmetric key with AES algorithm

        types: 
            validate signature
            decrypt file
            validate signature and decrypt file
        """
        if action == "validate_signature":
            try:
                # get public key of user A
                public_key_a = load_public_key(username_a)

                # read file data from signed directory
                with open(f"signed/{uploaded_file.filename}", "rb") as file:
                    file_content = file.read()
                print("here")
                # split the file content into text and signature using the separator
                text, _, signature_in_file = file_content.partition(custom_delimiter)

                """
                    verify signature with the data using the public key of user A using PSS(Probabilistic signature scheme) padding and SHA-256 hash.
                    Thanks to this process we can verify that user A send this text.
                    source = https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
                """
                public_key_a.verify(
                    signature_in_file,
                    text,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                # if process is successfully finished, display information
                result_message = "Signature is valid. The file came from User A."

            except Exception as e:
                # if there is an error, display error information
                result_message = f"Error validating signature: {str(e)}"

        elif action == "decrypt":
            try:
                # get private key of user B
                private_key_b = load_private_key(username_b)

                # read file data from encrypted text directory
                with open(f"encrypted/{uploaded_file.filename}", "rb") as file:
                    encrypted_data = file.read()

                # split the file content into ciphertext and encrypted_key_in_text using the separator
                encrypted_key_in_text, _, ciphertext = encrypted_data.partition(
                    custom_delimiter
                )

                """
                Use decryption with the OAEP(Optimal asymmetric encryption padding) padding scheme and SHA-256 as the hash function to get symmetric key                
                source: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
                """
                symmetric_key = private_key_b.decrypt(
                    encrypted_key_in_text,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # decrypt ciphertext with AES algorithm using symmetric key thanks to decrypt_symmetric_key i created as custom function
                decrypted_data = decrypt_symmetric_key(ciphertext, symmetric_key)

                # if process is successfully finished, display information and decrypted ciphertext content
                result_message = (
                    f"File decrypted successfully:\n{decrypted_data.decode('utf-8')}"
                )
            except Exception as e:
                # if there is an error, display error information
                result_message = f"Error decrypting file: {str(e)}"

        elif action == "decrypt_and_verify_signature":
            try:
                # get public key of user A
                public_key_a = load_public_key(username_a)

                # get private key of user B
                private_key_b = load_private_key(username_b)

                # read file data from signed and encrypted directory
                with open(
                    f"signed_and_encrypted/{uploaded_file.filename}", "rb"
                ) as file:
                    encrypted_signed_data = file.read()

                # split the file content into ciphertext, encrypted_key_in_text, and
                # signature using the separator
                (
                    encrypted_key_in_text,
                    ciphertext,
                    signature_in_text,
                ) = encrypted_signed_data.split(custom_delimiter)

                """
                Use decryption with the OAEP(Optimal asymmetric encryption padding) padding scheme and SHA-256 as the hash function to get symmetric key                
                source: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
                """
                symmetric_key = private_key_b.decrypt(
                    encrypted_key_in_text,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # decrypt ciphertext with AES algorithm using symmetric key thanks to decrypt_symmetric_key i created as custom function
                decrypted_data = decrypt_symmetric_key(ciphertext, symmetric_key)

                """
                    verify signature with the data using the public key of user A using PSS(Probabilistic signature scheme) padding and SHA-256 hash.
                    Thanks to this process we can verify that user A send this text.
                    source = https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
                """
                public_key_a.verify(
                    signature_in_text,
                    decrypted_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                # if process is successfully finished, display information and decrypted ciphertext content
                result_message = f"File decrypted and signature verified successfully:\n{decrypted_data.decode('utf-8')}"
            except Exception as e:
                # if there is an error, display error information
                result_message = f"Error decrypting and verifying signature: {str(e)}"

        flash(result_message)

    # render jinja2 template using render_template function to show user A as interface
    return render_template("user_b.html")


if __name__ == "__main__":
    app.run(debug=True)
