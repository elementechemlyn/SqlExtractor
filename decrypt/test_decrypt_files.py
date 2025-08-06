import pytest
import os
import sys
import glob
from io import StringIO

# PyCryptodome imports for key generation, encryption, and exceptions
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256

from decrypt_files import decrypt_file_with_private_key, main

class InvalidTag(Exception):
    pass

# Helper function for encryption, similar to sql_exporter.py's encrypt_file_with_public_key
def _encrypt_for_test(file_path: str, public_key_path: str, output_enc_path: str):
    """Encrypts a file using AES-GCM with an RSA-encrypted AES key for testing."""
    with open(public_key_path, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())

    aes_key = os.urandom(32) # 256-bit AES key
    iv = os.urandom(16)      # 128-bit IV for AES GCM

    with open(file_path, "rb") as f:
        plaintext = f.read()

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    with open(output_enc_path, "wb") as f:
        f.write(len(encrypted_aes_key).to_bytes(4, 'big'))
        f.write(encrypted_aes_key) # Encrypted AES key
        f.write(iv)                # Initialization Vector
        f.write(tag)               # Authentication Tag
        f.write(ciphertext)        # Encrypted data

@pytest.fixture(scope="module")
def rsa_key_pair(tmp_path_factory):
    """Fixture to generate RSA public/private key pair for encryption/decryption testing."""
    key_dir = tmp_path_factory.mktemp("keys")
    private_key_path = key_dir / "private_key.pem"
    public_key_path = key_dir / "public_key.pem"

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)

    yield private_key_path, public_key_path

@pytest.fixture
def setup_decryption_env(monkeypatch, tmp_path, rsa_key_pair):
    """
    Fixture to set up common environment variables and a temporary directory
    for decryption tests, then clean them up.
    """
    private_key_path, public_key_path = rsa_key_pair
    test_dir = tmp_path / "decryption_test_data"
    test_dir.mkdir()

    # Set default environment variables for the main function
    monkeypatch.setenv('PRIVATE_KEY_PATH', str(private_key_path))
    monkeypatch.setenv('ENCRYPTED_INPUT_PATH', str(test_dir)) # Default to directory

    yield test_dir, private_key_path, public_key_path

# --- Test Cases for decrypt_files.py ---

def test_decrypt_single_file_direct_call(setup_decryption_env):
    """Test direct call to decrypt_file_with_private_key for a single file."""
    test_dir, private_key_path, public_key_path = setup_decryption_env
    original_content = b"This is a test string to be encrypted and then decrypted."
    plaintext_file = test_dir / "test_file.txt"
    encrypted_file = test_dir / "test_file.txt.enc"

    with open(plaintext_file, "wb") as f:
        f.write(original_content)

    _encrypt_for_test(str(plaintext_file), str(public_key_path), str(encrypted_file))

    # Call the decryption function directly
    decrypt_file_with_private_key(str(encrypted_file), str(private_key_path))

    decrypted_file = test_dir / "test_file.txt"
    assert decrypted_file.exists()
    with open(decrypted_file, "rb") as f:
        decrypted_content = f.read()
    assert decrypted_content == original_content

def test_main_decrypt_single_file_env_var(setup_decryption_env, monkeypatch):
    """Test main function decrypting a single file specified via ENCRYPTED_INPUT_PATH."""
    test_dir, private_key_path, public_key_path = setup_decryption_env
    original_content = b"Another test string for main function."
    plaintext_file = test_dir / "main_test_file.txt"
    encrypted_file = test_dir / "main_test_file.txt.enc"

    with open(plaintext_file, "wb") as f:
        f.write(original_content)

    _encrypt_for_test(str(plaintext_file), str(public_key_path), str(encrypted_file))

    monkeypatch.setenv('ENCRYPTED_INPUT_PATH', str(encrypted_file)) # Set path to single file

    main() # Call the main function

    decrypted_file = test_dir / "main_test_file.txt"
    assert decrypted_file.exists()
    with open(decrypted_file, "rb") as f:
        decrypted_content = f.read()
    assert decrypted_content == original_content

def test_main_decrypt_directory_of_files(setup_decryption_env, monkeypatch):
    """Test main function decrypting multiple files in a directory."""
    test_dir, private_key_path, public_key_path = setup_decryption_env
    
    contents = {
        "file1.txt": b"Content of file 1.",
        "file2.txt": b"Content of file 2 with some more data."
    }

    for name, content in contents.items():
        plaintext_file = test_dir / name
        encrypted_file = test_dir / (name + ".enc")
        with open(plaintext_file, "wb") as f:
            f.write(content)
        _encrypt_for_test(str(plaintext_file), str(public_key_path), str(encrypted_file))
        os.remove(plaintext_file) # Remove original to ensure decryption creates it

    monkeypatch.setenv('ENCRYPTED_INPUT_PATH', str(test_dir)) # Set path to directory

    main()

    for name, expected_content in contents.items():
        decrypted_file = test_dir / name
        assert decrypted_file.exists()
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()
        assert decrypted_content == expected_content

def test_main_missing_private_key_path_error(monkeypatch, capsys):
    """Test error when PRIVATE_KEY_PATH is missing."""
    monkeypatch.delenv('PRIVATE_KEY_PATH', raising=False)
    monkeypatch.setenv('ENCRYPTED_INPUT_PATH', '/tmp/dummy_encrypted.enc')
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: PRIVATE_KEY_PATH environment variable not set." in captured.err

def test_main_private_key_file_not_found_error(setup_decryption_env, monkeypatch, capsys):
    """Test error when private key file does not exist."""
    test_dir, _, _ = setup_decryption_env
    monkeypatch.setenv('PRIVATE_KEY_PATH', str(test_dir / "non_existent_key.pem"))
    monkeypatch.setenv('ENCRYPTED_INPUT_PATH', str(test_dir / "dummy.enc"))
    # Create a dummy encrypted file to avoid other errors
    (test_dir / "dummy.enc").touch()

    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: Private key file not found:" in captured.err

def test_main_missing_encrypted_input_path_error(monkeypatch, capsys, rsa_key_pair):
    """Test error when ENCRYPTED_INPUT_PATH is missing."""
    _, private_key_path = rsa_key_pair
    monkeypatch.setenv('PRIVATE_KEY_PATH', str(private_key_path))
    monkeypatch.delenv('ENCRYPTED_INPUT_PATH', raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: ENCRYPTED_INPUT_PATH environment variable not set." in captured.err

def test_main_encrypted_input_path_not_found_error(setup_decryption_env, monkeypatch, capsys):
    """Test error when ENCRYPTED_INPUT_PATH (file or directory) does not exist."""
    test_dir, private_key_path, _ = setup_decryption_env
    monkeypatch.setenv('ENCRYPTED_INPUT_PATH', str(test_dir / "non_existent_dir_or_file"))

    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: Encrypted input path not found:" in captured.err

def test_main_no_enc_files_in_directory_error(setup_decryption_env, monkeypatch, capsys):
    """Test error when ENCRYPTED_INPUT_PATH is a directory but contains no .enc files."""
    test_dir, private_key_path, _ = setup_decryption_env
    # Create a non-.enc file in the directory
    (test_dir / "some_file.txt").touch()
    monkeypatch.setenv('ENCRYPTED_INPUT_PATH', str(test_dir))

    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "No .enc files found in directory:" in captured.err

def test_decrypt_file_with_tampered_content_raises_invalid_tag(setup_decryption_env, monkeypatch, capsys):
    """Test that decryption fails with InvalidTag for tampered content."""
    test_dir, private_key_path, public_key_path = setup_decryption_env
    original_content = b"Original content."
    plaintext_file = test_dir / "tamper_test.txt"
    encrypted_file = test_dir / "tamper_test.txt.enc"

    with open(plaintext_file, "wb") as f:
        f.write(original_content)
    _encrypt_for_test(str(plaintext_file), str(public_key_path), str(encrypted_file))

    # Tamper with the encrypted file (e.g., change one byte in the ciphertext)
    with open(encrypted_file, "r+b") as f:
        f.seek(os.path.getsize(encrypted_file) - 10) # Seek near the end (ciphertext/tag)
        f.write(b'\x00') # Change one byte

    # Call the function directly and expect InvalidTag
    with pytest.raises(Exception): # PyCryptodome raises ValueError for tag mismatch
        decrypt_file_with_private_key(str(encrypted_file), str(private_key_path))

    # Verify that the specific error message is printed to stderr
    captured = capsys.readouterr()
    assert "Error: Authentication tag mismatch" in captured.err

