import argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def load_public_key(filename):
    try:
        with open(filename,'rb') as f:
            key_data = f.read()
            try:
                # For PEM format keys 
                return serialization.load_pem_public_key(key_data, backend=default_backend())
            except ValueError:
                # For DER format keys
                return serialization.load_der_public_key(key_data,backend=default_backend())
    except Exception as e:
        print(f"Failed to load public key from {filename} erros:{e}")


def load_private_key(filename):
    try:
        with open(filename,'rb') as f:
            key_data = f.read()
            try:
                # For PEM format keys 
                return serialization.load_pem_private_key(key_data, password = None, backend=default_backend()) 
            except ValueError:
                # For DER format keys
                return serialization.load_der_private_key(key_data, password = None, backend=default_backend()) 
    except Exception as e:
        print(f"Failed to load private key from {filename}, Error:{e}")
        

def encrypt_and_sign(dest_pub_key, snd_prv_key, input_file, output_file):
    symmetric_key = os.urandom(32) # 256-bit symmetric key as it is considered the most secure symmetric key size

    encrypted_symmetric_key = dest_pub_key.encrypt(symmetric_key,padding.OAEP(
                                                    mgf=padding.MGF1(algorithm=hashes.SHA256())
                                                    ,algorithm=hashes.SHA256(),label=None))
    try: 
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor() # Encryptor object to encrypt the plaintext
        cipher_text = encryptor.update(plaintext) + encryptor.finalize() # Encrypt the plaintext

        signature = snd_prv_key.sign(cipher_text, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),
                                                            hashes.SHA256())
    except Exception as e:
        print(f"Unable to read input file, Error:{e}")
    
    try:
        with open(output_file, 'wb') as f:
            f.write(len(encrypted_symmetric_key).to_bytes(2, byteorder='big')) # Allocates 2 bytes for length of encrypted symmetric key
            f.write(encrypted_symmetric_key)
            f.write(iv)
            f.write(encryptor.tag)
            f.write(len(signature).to_bytes(2, byteorder='big')) # Allocates 2 bytes for length of signature
            f.write(signature)
            f.write(cipher_text)
    except Exception as e:
        print(f"Unable to write to output file, Error:{e}")


def decrypt_verify(dest_prvt_key, sndr_pub_key,input_file,output_file):
    try:
        with open(input_file, 'rb') as f:
            key_size = int.from_bytes(f.read(2), byteorder='big')
            encrypted_symmetric_key = f.read(key_size)
            symmetric_key = dest_prvt_key.decrypt(encrypted_symmetric_key,
                                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(),label=None))
            iv = f.read(16)
            tag = f.read(16)
            sig_size = int.from_bytes(f.read(2), byteorder='big')
            signature = f.read(sig_size)
            cipher_text = f.read()

        try:
            sndr_pub_key.verify(
                signature,
                cipher_text,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            raise ValueError("Signature verification failed")
        
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor() # Decryptor object to decrypt the cipher text
        plaintext = decryptor.update(cipher_text) + decryptor.finalize() # Decrypt the cipher text
        try:
            with open(output_file, 'wb') as f:
                f.write(plaintext)
        except Exception as e:
            print("Unable to write to output file, Error:{e}")

    except Exception as e:
        print("Unable to read input file, Error:{e}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Command for encrytpion or decryption")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", action="store_true", help="Encryption mode") # Encryption mode
    group.add_argument("-d", action="store_true", help="Decryption mode") # Decryption mode

    parser.add_argument("key1", help="Destination public key for encryption and\
                        private key for decryption")
    parser.add_argument("key2", help="Sender public key for encryption and\
                        private key for decryption")
    parser.add_argument("input_file", help="Input file to be encrypted or decrypted")
    parser.add_argument("output_file", help="Output file to save the result")
    
    args = parser.parse_args()

    if args.e:
        dest_public_key = load_public_key(args.key1)
        sender_private_key = load_private_key(args.key2)
        encrypt_and_sign(dest_public_key, sender_private_key, args.input_file, args.output_file)
        print("File encrypted and signed successfully.")
    else:
        dest_private_key = load_private_key(args.key1)
        sender_public_key = load_public_key(args.key2)
        decrypt_verify(dest_private_key, sender_public_key, args.input_file, args.output_file)
        print("File decrypted and signature verified successfully.")

    

    