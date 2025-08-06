import pytest
import os
import sqlite3
import dask.dataframe as dd
from datetime import datetime
import sys
from io import StringIO
import glob

# Import the function to be tested and the settings object
from sql_exporter import extract_sql_to_file
from settings import settings as app_settings # Renamed to avoid conflict with fixture

# PyCryptodome imports for key generation and decryption in tests
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256

@pytest.fixture(scope="module")
def dummy_sqlite_db(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db_test") / "test_database.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            age INTEGER,
            is_active BOOLEAN,
            created_at TEXT
        )
    ''')
    users_data = [
        (1, 'Alice Smith', 'alice@example.com', 30, True, datetime(2023, 1, 15, 10, 0, 0).isoformat()),
        (2, 'Bob Johnson', 'bob@example.com', 24, False, datetime(2023, 2, 20, 11, 30, 0).isoformat()),
        (3, 'Charlie Brown', 'charlie@example.com', 35, True, datetime(2023, 3, 25, 12, 0, 0).isoformat()),
        (4, 'Diana Prince', 'diana@example.com', 28, True, datetime(2023, 4, 1, 13, 15, 0).isoformat()),
        (5, 'Eve Adams', 'eve@example.com', 42, False, datetime(2023, 5, 5, 14, 45, 0).isoformat()),
    ]
    cursor.executemany("INSERT INTO users (id, name, email, age, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?)", users_data)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY,
            product_name TEXT NOT NULL,
            price REAL
        )
    ''')
    products_data = [
        (101, 'Laptop', 1200.50),
        (102, 'Mouse', 25.00),
    ]
    cursor.executemany("INSERT INTO products (product_id, product_name, price) VALUES (?, ?, ?)", products_data)
    conn.commit()
    conn.close()
    yield db_path

@pytest.fixture(scope="module")
def rsa_key_pair(tmp_path_factory):
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
def setup_settings_and_output(monkeypatch, tmp_path, dummy_sqlite_db):
    output_dir = tmp_path / "output_data"
    output_dir.mkdir()
    monkeypatch.setattr(app_settings, 'DATABASE_URL', f'sqlite:///{dummy_sqlite_db}')
    monkeypatch.setattr(app_settings, 'OUTPUT_DIRECTORY', str(output_dir))
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'id')
    monkeypatch.setattr(app_settings, 'PUBLIC_KEY_PATH', None)
    monkeypatch.setattr(app_settings, 'REMOVE_UNENCRYPTED_FILES', True)
    monkeypatch.setattr(app_settings, 'SQL_QUERY', None)
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', None)
    monkeypatch.setattr(app_settings, 'CSV_ENCODING', 'utf-8')
    monkeypatch.setattr(app_settings, 'CSV_QUOTING', 'QUOTE_MINIMAL')
    monkeypatch.setattr(app_settings, 'CSV_DATE_FORMAT', None)
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    yield output_dir

# Helper function to read Dask output (CSV or Parquet)
def read_dask_output(output_dir, output_format):
    if output_format == 'csv':
        # Dask writes multiple CSVs, so read all from the directory
        ddf = dd.read_csv(f"{output_dir}/*.csv")
    elif output_format == 'parquet':
        # Dask writes multiple Parquet files, so read all from the directory
        ddf = dd.read_parquet(str(output_dir), index=False)
    else:
        raise ValueError("Unsupported output format for reading.")
    return ddf.compute() # Convert to pandas DataFrame for easy comparison

# Helper function to decrypt a file (for testing encryption)
def decrypt_file_with_private_key(encrypted_file_path: str, private_key_path: str) -> bytes:
    """
    Decrypts a file encrypted with encrypt_file_with_public_key using the private key.
    Returns the plaintext bytes.
    """
    with open(private_key_path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    with open(encrypted_file_path, "rb") as f:
        encrypted_aes_key_len = int.from_bytes(f.read(4), 'big')
        encrypted_aes_key = f.read(encrypted_aes_key_len)
        iv = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = AES.new(decrypted_aes_key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext


# --- Test Cases ---

def test_extract_table_to_csv(setup_settings_and_output, monkeypatch):
    """Test extracting data from a table to CSV."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')

    extract_sql_to_file()

    df_output = read_dask_output(output_dir, 'csv')
    assert not df_output.empty
    assert len(df_output) == 5
    assert list(df_output.columns) == ['id', 'name', 'email', 'age', 'is_active', 'created_at']
    assert df_output['name'].iloc[0] == 'Alice Smith'
    assert df_output['email'].iloc[1] == 'bob@example.com'

def test_extract_sql_query_to_csv(setup_settings_and_output, monkeypatch):
    """Test extracting data using a SQL query to CSV."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'SQL_QUERY', 'SELECT id, name, email FROM users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'id') # Index column must be in the selected columns

    extract_sql_to_file()

    df_output = read_dask_output(output_dir, 'csv')
    assert not df_output.empty
    assert len(df_output) == 5 
    assert list(df_output.columns) == ['id', 'name', 'email']
    assert 'Charlie Brown' in df_output['name'].values
    assert 'Eve Adams' in df_output['name'].values

def test_extract_table_to_parquet(setup_settings_and_output, monkeypatch):
    """Test extracting data from a table to Parquet."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'parquet')

    extract_sql_to_file()

    df_output = read_dask_output(output_dir, 'parquet')
    assert not df_output.empty
    assert len(df_output) == 5
    assert list(df_output.columns) == ['id','name', 'email', 'age', 'is_active', 'created_at']
    assert df_output['name'].iloc[0] == 'Alice Smith'
    assert df_output['age'].iloc[2] == 35

def test_extract_sql_query_to_parquet(setup_settings_and_output, monkeypatch):
    """Test extracting data using a SQL query to Parquet."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'SQL_QUERY', 'SELECT product_id, product_name, price FROM products')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'parquet')
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'product_id') # Index column must be in the selected columns

    extract_sql_to_file()

    df_output = read_dask_output(output_dir, 'parquet')
    assert not df_output.empty
    assert len(df_output) == 2
    assert list(df_output.columns) == ['product_id', 'product_name', 'price']
    #assert df_output['product_name'].iloc[0] == 'Laptop'
    #assert df_output['price'].iloc[1] == 25.00

def test_csv_encoding(setup_settings_and_output, monkeypatch):
    """Test CSV encoding option."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    monkeypatch.setattr(app_settings, 'CSV_ENCODING', 'latin-1')

    extract_sql_to_file()

    ddf = dd.read_csv(f"{output_dir}/*.csv", encoding='latin-1')
    df_output = ddf.compute()
    assert not df_output.empty
    assert df_output['name'].iloc[0] == 'Alice Smith'

def test_csv_quoting_all(setup_settings_and_output, monkeypatch):
    """Test CSV QUOTE_ALL option."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    monkeypatch.setattr(app_settings, 'CSV_QUOTING', 'QUOTE_ALL')

    extract_sql_to_file()

    df_output = read_dask_output(output_dir, 'csv')
    assert not df_output.empty
    assert df_output['email'].iloc[0] == 'alice@example.com'

def test_csv_date_format(setup_settings_and_output, monkeypatch):
    """Test CSV date formatting option."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    monkeypatch.setattr(app_settings, 'CSV_DATE_FORMAT', '%Y-%m-%d %H:%M')
    monkeypatch.setattr(app_settings, 'DATE_COLUMNS', ['created_at',])

    extract_sql_to_file()

    df_output = read_dask_output(output_dir, 'csv')
    assert not df_output.empty
    assert df_output['created_at'].iloc[0] == '2023-01-15 10:00'
    assert df_output['created_at'].iloc[1] == '2023-02-20 11:30'

def test_encryption_csv_remove_original_true(setup_settings_and_output, monkeypatch, rsa_key_pair):
    """Test encryption for CSV output with REMOVE_UNENCRYPTED_FILES=True (default)."""
    output_dir = setup_settings_and_output
    private_key_path, public_key_path = rsa_key_pair

    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    monkeypatch.setattr(app_settings, 'PUBLIC_KEY_PATH', str(public_key_path))
    monkeypatch.setattr(app_settings, 'REMOVE_UNENCRYPTED_FILES', True) # Explicitly true

    extract_sql_to_file()

    # Verify encrypted files exist
    encrypted_files = glob.glob(os.path.join(output_dir, '*.csv.enc'))
    assert len(encrypted_files) > 0

    # Verify original files are removed
    original_files = glob.glob(os.path.join(output_dir, '*.csv'))
    assert len(original_files) == 0

    # Decrypt and verify content of the first encrypted file
    decrypted_content = decrypt_file_with_private_key(encrypted_files[0], str(private_key_path))

    # Write decrypted content to a temp file to be read by Dask
    temp_decrypted_path = output_dir / "decrypted_part.csv"
    with open(temp_decrypted_path, "wb") as f:
        f.write(decrypted_content)

    decrypted_df_part = dd.read_csv(str(temp_decrypted_path)).compute()
    assert not decrypted_df_part.empty
    assert any(name in decrypted_df_part['name'].values for name in ['Alice Smith', 'Bob Johnson', 'Charlie Brown', 'Diana Prince', 'Eve Adams'])


def test_encryption_parquet_remove_original_false(setup_settings_and_output, monkeypatch, rsa_key_pair):
    """Test encryption for Parquet output with REMOVE_UNENCRYPTED_FILES=False."""
    output_dir = setup_settings_and_output
    private_key_path, public_key_path = rsa_key_pair

    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'parquet')
    monkeypatch.setattr(app_settings, 'PUBLIC_KEY_PATH', str(public_key_path))
    monkeypatch.setattr(app_settings, 'REMOVE_UNENCRYPTED_FILES', False) # Explicitly false

    extract_sql_to_file()

    # Verify encrypted files exist
    encrypted_files = glob.glob(os.path.join(output_dir, '*.parquet.enc'))
    assert len(encrypted_files) > 0

    # Verify original files ARE NOT removed
    original_files = glob.glob(os.path.join(output_dir, '*.parquet'))
    assert len(original_files) > 0

    # Decrypt and verify content of the first encrypted file
    decrypted_content = decrypt_file_with_private_key(encrypted_files[0], str(private_key_path))

    # Write decrypted content to a temp file to be read by Dask
    temp_decrypted_path = output_dir / "decrypted_part.parquet"
    with open(temp_decrypted_path, "wb") as f:
        f.write(decrypted_content)

    decrypted_df_part = dd.read_parquet(str(temp_decrypted_path)).compute()
    assert not decrypted_df_part.empty
    assert any(name in decrypted_df_part['name'].values for name in ['Alice Smith', 'Bob Johnson', 'Charlie Brown', 'Diana Prince', 'Eve Adams'])


# --- Error Handling Tests ---

def test_missing_database_url(monkeypatch, capsys):
    """Test error when DATABASE_URL is missing."""
    monkeypatch.setattr(app_settings, 'DATABASE_URL', None)
    monkeypatch.setattr(app_settings, 'OUTPUT_DIRECTORY', '/tmp/test_dir')
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'id')
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')

    extract_sql_to_file()

    captured = capsys.readouterr()
    assert "Error: DATABASE_URL environment variable not set." in captured.err

def test_missing_output_directory(monkeypatch, capsys, dummy_sqlite_db):
    """Test error when OUTPUT_DIRECTORY is missing."""
    monkeypatch.setattr(app_settings, 'DATABASE_URL', f'sqlite:///{dummy_sqlite_db}')
    monkeypatch.setattr(app_settings, 'OUTPUT_DIRECTORY', None)
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'id')
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')

    extract_sql_to_file()

    captured = capsys.readouterr()
    assert "Error: OUTPUT_DIRECTORY environment variable not set." in captured.err

def test_missing_db_index_column(monkeypatch, capsys, dummy_sqlite_db):
    """Test error when DB_INDEX_COLUMN is missing."""
    monkeypatch.setattr(app_settings, 'DATABASE_URL', f'sqlite:///{dummy_sqlite_db}')
    monkeypatch.setattr(app_settings, 'OUTPUT_DIRECTORY', '/tmp/test_dir')
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', None)
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')

    extract_sql_to_file()

    captured = capsys.readouterr()
    assert "Error: DB_INDEX_COLUMN environment variable not set." in captured.err

def test_both_sql_query_and_database_table_set(monkeypatch, capsys, dummy_sqlite_db):
    """Test error when both SQL_QUERY and DATABASE_TABLE are set."""
    monkeypatch.setattr(app_settings, 'DATABASE_URL', f'sqlite:///{dummy_sqlite_db}')
    monkeypatch.setattr(app_settings, 'OUTPUT_DIRECTORY', '/tmp/test_dir')
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'id')
    monkeypatch.setattr(app_settings, 'SQL_QUERY', 'SELECT * FROM users')
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')

    extract_sql_to_file()

    captured = capsys.readouterr()
    assert "Error: Both SQL_QUERY and DATABASE_TABLE are set." in captured.err

def test_neither_sql_query_nor_database_table_set(monkeypatch, capsys, dummy_sqlite_db):
    """Test error when neither SQL_QUERY nor DATABASE_TABLE is set."""
    monkeypatch.setattr(app_settings, 'DATABASE_URL', f'sqlite:///{dummy_sqlite_db}')
    monkeypatch.setattr(app_settings, 'OUTPUT_DIRECTORY', '/tmp/test_dir')
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'id')
    monkeypatch.setattr(app_settings, 'SQL_QUERY', None)
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', None)

    extract_sql_to_file()

    captured = capsys.readouterr()
    assert "Error: Neither SQL_QUERY nor DATABASE_TABLE is set." in captured.err

def test_invalid_output_format(setup_settings_and_output, monkeypatch, capsys):
    """Test error when an invalid OUTPUT_FORMAT is provided."""
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'invalid_format')

    extract_sql_to_file()

    captured = capsys.readouterr()
    assert "Error: Invalid OUTPUT_FORMAT 'invalid_format'. Must be 'csv' or 'parquet'." in captured.err

def test_public_key_path_not_found(setup_settings_and_output, monkeypatch, capsys):
    """Test error when PUBLIC_KEY_PATH is provided but file does not exist."""
    monkeypatch.setattr(app_settings, 'DATABASE_TABLE', 'users')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    monkeypatch.setattr(app_settings, 'PUBLIC_KEY_PATH', '/non/existent/key.pem')

    extract_sql_to_file()

    captured = capsys.readouterr()
    assert "Error: PUBLIC_KEY_PATH specified but file not found: /non/existent/key.pem" in captured.err

def test_no_data_extracted(setup_settings_and_output, monkeypatch):
    """Test scenario where no data is extracted (e.g., empty query result)."""
    output_dir = setup_settings_and_output
    monkeypatch.setattr(app_settings, 'SQL_QUERY', 'SELECT * FROM users WHERE id = 999')
    monkeypatch.setattr(app_settings, 'OUTPUT_FORMAT', 'csv')
    monkeypatch.setattr(app_settings, 'DB_INDEX_COLUMN', 'id')

    extract_sql_to_file()

    df_output = read_dask_output(output_dir, 'csv')
    assert df_output.empty
    assert len(df_output) == 0

