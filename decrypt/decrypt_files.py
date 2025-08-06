import os
import sys
import glob
import tempfile

# PyCryptodome imports for decryption
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256

class InvalidTag(Exception):
    pass

def decrypt_file_with_private_key(encrypted_file_path: str, private_key_path: str):
    """
    Decrypts a single file that was encrypted using encrypt_file_with_public_key.
    The output is a new file without the .enc extension.
    """
    print(f"Decrypting file: {encrypted_file_path}")
    try:
        # Load Private Key
        with open(private_key_path, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())

        # Read Encrypted Data Components
        with open(encrypted_file_path, "rb") as f:
            encrypted_aes_key_len = int.from_bytes(f.read(4), 'big')
            encrypted_aes_key = f.read(encrypted_aes_key_len) # Encrypted AES key
            iv = f.read(16)                                  # Initialization Vector
            tag = f.read(16)                                 # Authentication Tag
            ciphertext = f.read()                            # Encrypted data

        # Decrypt AES Key with RSA Private Key
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Decrypt File Content with AES-GCM
        cipher_aes = AES.new(decrypted_aes_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Save Decrypted Data
        if encrypted_file_path.endswith('.enc'):
            output_dec_path = encrypted_file_path[:-4]
        else:
            output_dec_path = encrypted_file_path + ".decrypted" # Fallback if no .enc

        with open(output_dec_path, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted to: {output_dec_path}")

    except ValueError as e:
        print(f"Error: Authentication tag mismatch for {encrypted_file_path}. Data may be tampered with or key is incorrect.", file=sys.stderr)
        raise InvalidTag from e
    except Exception as e:
        print(f"Error decrypting {encrypted_file_path}: {e}", file=sys.stderr)
        raise

def main():
    """
    Main function to orchestrate file decryption based on environment variables.
    Detailed usage instructions are in README.md.
    """
    print("Starting file decryption process...")

    private_key_path = os.getenv('PRIVATE_KEY_PATH')
    encrypted_input_path = os.getenv('ENCRYPTED_INPUT_PATH')

    if not private_key_path:
        print("Error: PRIVATE_KEY_PATH environment variable not set. See README.md.", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(private_key_path):
        print(f"Error: Private key file not found: {private_key_path}", file=sys.stderr)
        sys.exit(1)
    if not encrypted_input_path:
        print("Error: ENCRYPTED_INPUT_PATH environment variable not set. See README.md.", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(encrypted_input_path):
        print(f"Error: Encrypted input path not found: {encrypted_input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Private Key Path: {private_key_path}")
    print(f"Encrypted Input Path: {encrypted_input_path}")

    files_to_decrypt = []
    if os.path.isfile(encrypted_input_path):
        files_to_decrypt.append(encrypted_input_path)
    elif os.path.isdir(encrypted_input_path):
        # Find all .enc files in the directory
        files_to_decrypt = glob.glob(os.path.join(encrypted_input_path, '*.enc'))
        if not files_to_decrypt:
            print(f"No .enc files found in directory: {encrypted_input_path}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Error: ENCRYPTED_INPUT_PATH '{encrypted_input_path}' is neither a file nor a directory.", file=sys.stderr)
        sys.exit(1)

    for file_path in files_to_decrypt:
        try:
            decrypt_file_with_private_key(file_path, private_key_path)
        except Exception:
            print(f"Decryption failed for {file_path}. Skipping to next file.", file=sys.stderr)

    print("Decryption process completed.")

if __name__ == "__main__":
    main()

