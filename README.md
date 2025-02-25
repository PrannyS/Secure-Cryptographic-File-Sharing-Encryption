# Secure-Cryptographic-File-Sharing-Encryption
![Status](https://img.shields.io/badge/Status-Completed-green)
![Tech](https://img.shields.io/badge/Tools-python%2C%20bash-blue)

## 📌 Overview 
This repository contains two cryptographic implementations designed to provide secure file sharing and encryption, ensuring **Confidentiality, Integrity, and Authentication**. The projects focus on using a combination of **symmetric encryption, asymmetric encryption, and hashing algorithms** to protect sensitive files.

### Projects Covered

1. Secure Group File Sharing (Bash + OpenSSL)
- Uses ECC (Elliptic Curve Cryptography) and ECDH (Elliptic Curve Diffie-Hellman) for key exchange.
- Encrypts files using AES-256-GCM and signs them with ECDSA.
- Generates individual cryptographic envelopes for each recipient.
- Verifies file integrity through digital signatures.

2. Secure Encryption & Signing (Python + Cryptography Library)
- Implements hybrid encryption using AES-256-GCM for encryption and RSA/ECC for key exchange.
- Supports both PEM and DER key formats.
- Verifies file integrity and authenticity using digital signatures.
- Efficient for large binary files.

---

## 📖 Table of Contents
- [Key Topics Covered](#key-topics-covered)  
- [Files Included](#files-included)  
- [Tools & Technologies Used](#tools--technologies-used)  
- [Methodology](#methodology)  
  - [Environment Setup](#0️⃣-environment-setup)  
  - [Secure Group File Sharing (Bash + OpenSSL)](#1️⃣-secure-group-file-sharing-bash--openssl)  
  - [Secure Encryption & Signing (Python + Cryptography Library)](#2️⃣-secure-encryption--signing-python--cryptography-library)   
- [Security Measures](#security-measures)  
- [Learning Outcomes](#learning-outcomes)  
- [Contact](#contact)  
- [Acknowledgements](#acknowledgements)

---

## Key Topics Covered 
- **Secure Group File Sharing:** Encrypting and signing files for multiple recipients using OpenSSL.
- **ECC & ECDH:** Secure key exchange using elliptic curve cryptography.
- **Key Derivation Functions (KDFs):** Using PBKDF2, Argon2, or Scrypt for key generation.
- **Hybrid Cryptography:** Combining symmetric and asymmetric encryption for efficiency.
- **Signature Verification:** Ensuring data authenticity and integrity.

---

## Files Included  
| File Name | Description |  
|-----------|------------|  
| `screenshots/*` | All the screenshots to execute this attack |
| `flowgraphs/fm_receive.grc` | GNU receiver flow graph|
| `flowgraphs/fm_transmit.grc` | GNU transmitter flow graph|


---

## Tools & Technologies Used  
- **OpenSSL (Bash)** – Cryptographic operations in shell scripts
- **Python Cryptography Library** – Secure encryption & digital signatures
- **Elliptic Curve Cryptography (ECC**)** – Efficient key exchange & signatures
- **AES-256-GCM** – Authenticated encryption for confidentiality
- **SHA-512 Hashing** – Integrity verification

---

## Methodology

### 0️⃣ Environment Setup

- For lab 1
```bash
sudo apt install openssl
chmod +x crypto.sh
```

- For lab 2
```bash
pip install cryptography
```

### 1️⃣ Secure Group File Sharing (Bash + OpenSSL)
#### Encryption & Signing (Sender)
```bash
./crypto.sh -sender <receiver1_pub> <receiver2_pub> <receiver3_pub> <sender_priv> <plaintext_file> <zip_filename>
```
- Generates a unique encryption key using ECDH + KDF.
- Encrypts the file using AES-256-GCM.
- Signs the encrypted file using ECDSA.
- Packages the encrypted file and signature into a ZIP archive.

#### Decryption & Verification (Receiver)
```bash
./crypto.sh -receiver <receiver_priv> <sender_pub> <zip_file> <plaintext_file>
```
- Extracts the encrypted file and signature.
- Verifies the ECDSA signature to ensure authenticity.
- Decrypts the file only if the recipient's private key matches the envelope.


### 2️⃣ Secure Encryption & Signing (Python + Cryptography Library)
#### Encryption & Signing (Sender)
```bash
python fcrypt.py -e destination_public_key.pem sender_private_key.pem input.txt encrypted_file.enc
```
- Generates a symmetric encryption key.
- Encrypts the file using AES-256-GCM.
- Signs the file with ECDSA or RSA

#### Decryption & Verification (Receiver)
```bash
python fcrypt.py -d destination_private_key.pem sender_public_key.pem encrypted_file.enc decrypted_output.txt
```
- Verifies the digital signature.
- Decrypts the file if verification is successful.

---

## Security Measures
✅ ***Elliptic Curve Cryptography (ECC):*** Ensures strong key security with minimal overhead.
✅ ***AES-256-GCM Encryption:*** Provides confidentiality and authenticated encryption.
✅ ***Digital Signatures:*** Uses ECDSA to validate sender authenticity.
✅ ***Key Derivation Functions (KDFs):*** Strengthens encryption keys against brute-force attacks.
✅ ***Secure File Handling:*** Intermediate files are deleted to prevent leaks.

---

## Learning Outcomes
- Implemented secure group file sharing using ECC & OpenSSL.
- Developed a hybrid encryption system using Python & the Cryptography library.
- Understood key exchange mechanisms using ECDH.
- Applied digital signatures to ensure data authenticity.
- Implemented best security practices for file encryption

---

## Contact
For any inquiries, feel free to reach out via:
📌 LinkedIn: www.linkedin.com/in/pranavs07

---

## Acknowledgements
This project was developed as part of a cryptography lab course, under the guidance of Prof. Guevara Noubir.
