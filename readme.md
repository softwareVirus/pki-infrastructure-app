# PKI Infrastructure with Flask - README.md

This project implements a Public Key Infrastructure (PKI) using Flask, providing a simple web-based interface for two users (User A and User B) to perform secure file operations such as signing, encryption, and their combinations.

## Requirements

- Python >= 3.8

## Getting Started

1. **Clone the Repository:**
   ```bash
   cd cyber-project
   ```
2. **Install Dependencies:**
   ```bash
	python3 -m venv .venv
   ```

3. **Install Dependencies:**
   ```bash
   .venv/Scripts/activate
   ```
4. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Generate Keys:**
   Run the `__init__.py` script to generate the required key pairs for User A and User B. This script creates private and public key files for each user in the `keys` directory.
   ```bash
   python __init__.py
   ```

6. **Run the Flask App:**
   ```bash
   flask --app app.py run
   ```

   The Flask app will start running at `http://127.0.0.1:5000/` (by default).

## User A Operations

User A has the ability to sign files, encrypt files, and perform both signing and encryption on files.

- **Sign File:**
  - Access the User A interface at `http://127.0.0.1:5000/user_a`.
  - Choose the "Sign" action and select a file to upload.
  - The signed file will be saved in the `signed` directory.

- **Encrypt File:**
  - Access the User A interface at `http://127.0.0.1:5000/user_a`.
  - Choose the "Encrypt" action and select a file to upload.
  - The encrypted file will be saved in the `encrypted` directory.

- **Sign and Encrypt File:**
  - Access the User A interface at `http://127.0.0.1:5000/user_a`.
  - Choose the "Sign and Encrypt" action and select a file to upload.
  - The signed and encrypted file will be saved in the `signed_and_encrypted` directory.

## User B Operations

User B can validate signatures, decrypt files, and perform both signature validation and decryption.

- **Validate Signature:**
  - Access the User B interface at `http://127.0.0.1:5000/user_b`.
  - Choose the "Validate Signature" action and select a signed file to upload.
  - User B will be notified if the signature is valid and the file originated from User A.

- **Decrypt File:**
  - Access the User B interface at `http://127.0.0.1:5000/user_b`.
  - Choose the "Decrypt" action and select an encrypted file to upload.
  - The decrypted file content will be displayed.

- **Decrypt and Verify Signature:**
  - Access the User B interface at `http://127.0.0.1:5000/user_b`.
  - Choose the "Decrypt and Verify Signature" action and select a signed and encrypted file to upload.
  - User B will be notified if the signature is valid, and the decrypted file content will be displayed.

## Directory Structure

- `keys/`: Contains generated private and public key pairs for User A and User B.
- `uploads/`: Temporary storage for user-uploaded files.
- `signed/`: Location for storing files signed by User A.
- `encrypted/`: Location for storing files encrypted by User A for User B.
- `signed_and_encrypted/`: Location for storing files signed and encrypted by User A for User B.

## Cryptographic Techniques Used in the Project

This Flask-based Public Key Infrastructure (PKI) project employs various cryptographic techniques to ensure the security and integrity of file operations. Below are the key cryptographic techniques used in the implementation:

#### 1. **Asymmetric Encryption (RSA)**
   - **Purpose:** Used for secure communication between User A and User B.
   - **Implementation:**
     - Key Generation: RSA key pairs (public and private) are generated using `cryptography.hazmat.primitives.asymmetric.rsa`.
     - File Encryption: Public key encryption is employed for encrypting symmetric keys, ensuring only the intended recipient (User B) can decrypt the file.

#### 2. **Symmetric Encryption (AES)**
   - **Purpose:** Used for efficient bulk data encryption.
   - **Implementation:**
     - Key Generation: Symmetric keys are derived using the PBKDF2-HMAC key derivation function.
     - File Encryption: AES encryption is applied to the actual file content, securing the confidentiality of the data.

#### 3. **Digital Signatures (RSA-PSS)**
   - **Purpose:** Ensures the authenticity and integrity of files signed by User A.
   - **Implementation:**
     - Signing: Files are signed using RSA-PSS (Probabilistic Signature Scheme) with SHA-256 hash function.
     - Verification: User B can verify the signature using User A's public key.

#### 4. **Padding Schemes (OAEP)**
   - **Purpose:** Adds security features to asymmetric encryption.
   - **Implementation:**
     - OAEP Padding: Optimal Asymmetric Encryption Padding (OAEP) is applied for secure encryption and decryption using RSA.

#### 5. **File Separation with Custom Delimiter**
   - **Purpose:** Distinguishes different components of the processed files.
   - **Implementation:**
     - Custom Delimiter: Files are separated into distinct sections (e.g., encrypted key, ciphertext, signature) using a custom delimiter (`custom_delimiter`), facilitating proper parsing during operations.

#### 6. **Hash Functions (SHA-256)**
   - **Purpose:** Used for hashing and integrity verification.
   - **Implementation:**
     - SHA-256: Applied in various cryptographic operations, including key derivation, digital signatures, and padding schemes.

These cryptographic techniques collectively provide a secure foundation for file operations, ensuring confidentiality, integrity, and authenticity in the PKI infrastructure implemented in this Flask project.

## Screenshots
![image](https://github.com/softwareVirus/pki-infrastructure-app/assets/63147096/cc3e9a03-071d-4958-aaca-618bd15f96cf)
![image](https://github.com/softwareVirus/pki-infrastructure-app/assets/63147096/37680173-528b-432b-88e8-f7d393944182)
![image](https://github.com/softwareVirus/pki-infrastructure-app/assets/63147096/acd5f4b9-5597-4622-84de-99c1c9a7a5a0)

## Notes

- The `__init__.py` script generates RSA key pairs for User A and User B. If keys already exist, it will not generate new ones.

- For security purposes, it is recommended to use a stronger secret key than the one specified in `app.py`. Modify the `SECRET_KEY` in `app.py` accordingly.

- This project is intended for educational purposes and may require further enhancements for production use, such as error handling, secure key management, and proper file handling.

Feel free to explore and extend the functionality as needed. Enjoy secure file operations with Flask and PKI!
