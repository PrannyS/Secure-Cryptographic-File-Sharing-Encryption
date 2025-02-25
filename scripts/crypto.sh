#!/bin/bash

error_exit() {
  echo "$1" 1>&2
  exit 1
}


if ! command -v openssl &> /dev/null; then # This checks if openssl is installed or not.
    error_exit "OpenSSL is not installed. ERROR sudeendra.p"
fi



if [ "$1" == "-sender" ]; then
  receiver1_pub="$2"
  receiver2_pub="$3"
  receiver3_pub="$4"
  sender_priv="$5"
  plaintext_file="$6"
  zip_filename="$7"

  if [ -z "$receiver1_pub" ] || [ -z "$receiver2_pub" ] || [ -z "$receiver3_pub" ] || [ -z "$sender_priv" ] || [ -z "$plaintext_file" ] || [ -z "$zip_filename" ]; then
    error_exit "Incorrect arguments: ./crypto.sh -sender <receiver1_pub> <receiver2_pub> <receiver3_pub> <sender_priv> <plaintext_file> <zip_filename>. ERROR sudeendra.p"
  fi

  symmetric_key=$(openssl rand -base64 32) # Generates a random symmetric key.
  encrypted_file="encrypted.dat"
  openssl enc -aes-256-cbc -salt -in "$plaintext_file" -out "$encrypted_file" -k "$symmetric_key" -pbkdf2

  signature_file="signature.sig"
  openssl dgst -sha256 -sign "$sender_priv" -out "$signature_file" "$encrypted_file"

  create_envelope() {
    local receiver_pub="$1"
    local envelope_file="$2"
    
    # Perform ECDH key exchange
    shared_secret=$(openssl pkeyutl -derive -inkey "$sender_priv" -peerkey "$receiver_pub" -out shared_secret.bin)
    
    # Use the shared secret as a key for encrypting the symmetric key
    openssl enc -aes-256-cbc -salt -in <(echo -n "$symmetric_key") -out "$envelope_file" -k "$shared_secret" -pbkdf2
    
    rm shared_secret.bin
  }

  # Creating envelopes for each receiver.
  create_envelope "$receiver1_pub" "envelope1.enc"
  create_envelope "$receiver2_pub" "envelope2.enc"
  create_envelope "$receiver3_pub" "envelope3.enc"

  zip "$zip_filename" "$encrypted_file" "$signature_file" envelope*.enc

  rm "$encrypted_file" "$signature_file" envelope*.enc




elif [ "$1" == "-receiver" ]; then
  receiver_priv="$2"
  sender_pub="$3"
  zip_file="$4"
  plaintext_file="$5"

  if [ -z "$receiver_priv" ] || [ -z "$sender_pub" ] || [ -z "$zip_file" ] || [ -z "$plaintext_file" ]; then
    error_exit "Incorrect arguments: ./crypto.sh -receiver <receiver_priv> <sender_pub> <zip_file> <plaintext_file> ERROR sudeendra.p"
  fi

  unzip "$zip_file"

  openssl dgst -sha256 -verify "$sender_pub" -signature signature.sig encrypted.dat
  if [ $? -ne 0 ]; then
    error_exit "Signature verification failed. ERROR sudeendra.p"
  fi


  decrypt_symmetric_key() {
    local envelope_file="$1"
    
    # Perform ECDH key exchange
    shared_secret=$(openssl pkeyutl -derive -inkey "$receiver_priv" -peerkey "$sender_pub" -out shared_secret.bin)
    
    # Use the shared secret to decrypt the symmetric key
    symmetric_key=$(openssl enc -aes-256-cbc -d -salt -in "$envelope_file" -k "$shared_secret" -pbkdf2)
    
    rm shared_secret.bin
    echo "$symmetric_key"
  }


  for envelope in envelope*.enc; do
    symmetric_key=$(decrypt_symmetric_key "$envelope")
    if [ -n "$symmetric_key" ]; then
      break
    fi
  done

  if [ -z "$symmetric_key" ]; then
    error_exit "Digital Envelope Decryption failed. Private key provided cannot access any envelopes ERROR sudeendra.p"
  fi

  openssl enc -aes-256-cbc -d -salt -in encrypted.dat -out "$plaintext_file" -k "$symmetric_key" -pbkdf2

  rm encrypted.dat signature.sig envelope*.enc



else
  echo "Usage: ./crypto.sh -sender <receiver1_pub> <receiver2_pub> <receiver3_pub> <sender_priv> <plaintext_file> <zip_filename> OR ../crypto.sh -sender <receiver1_pub> <receiver2_pub> <receiver3_pub> <sender_priv> <plaintext_file> <zip_filename>. Error sudeendra.p"
  exit 1
fi

exit 0
