import os
import dask.dataframe as dd
from sqlalchemy import create_engine, text, select
import sys
import csv
import glob
import re

# Import settings from the new settings.py file
from settings import settings

# PyCryptodome imports for encryption
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256

def encrypt_file_with_public_key(file_path: str, public_key_path: str, remove_original: bool):
    """
    Encrypts a single file using a hybrid approach: AES for data, RSA for the AES key.
    The output is a new file with a .enc extension. Optionally removes the original file.
    """
    print(f"Encrypting file: {file_path}")
    try:
        # Load Public Key
        with open(public_key_path, "rb") as key_file:
            public_key = RSA.import_key(key_file.read())

        # Generate Symmetric Key (AES) and IV
        aes_key = os.urandom(32) # 256-bit AES key
        iv = os.urandom(16) # 128-bit IV for AES GCM

        # Read File Content
        # TODO This is going to break with a big file. Don't load this all into memory.
        with open(file_path, "rb") as f:
            plaintext = f.read()

        # Encrypt File Content with AES-GCM
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        # Encrypt AES Key with RSA Public Key
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Save Encrypted Data
        output_enc_path = file_path + ".enc"
        with open(output_enc_path, "wb") as f:
            # Store length of encrypted_aes_key (4 bytes)
            f.write(len(encrypted_aes_key).to_bytes(4, 'big'))
            f.write(encrypted_aes_key) # Encrypted AES key
            f.write(iv)                # Initialization Vector
            f.write(tag)               # Authentication Tag
            f.write(ciphertext)        # Encrypted data

        print(f"File encrypted to: {output_enc_path}")

        # Optionally remove the original unencrypted file
        if remove_original:
            os.remove(file_path)
            print(f"Original file removed: {file_path}")

    except Exception as e:
        print(f"Error encrypting {file_path}: {e}", file=sys.stderr)
        raise # Re-raise to indicate failure


def extract_sql_to_file():
    """
    Extracts data from a SQL database to CSV or Parquet files using Dask,
    with an option to encrypt the output and optionally remove unencrypted files.
    Detailed usage instructions and environment variable descriptions are in README.md.
    """
    print("Starting SQL to file extraction...")

    # Access settings from the imported settings object
    database_url = settings.DATABASE_URL
    output_directory = settings.OUTPUT_DIRECTORY
    db_index_column = settings.DB_INDEX_COLUMN
    output_format = settings.OUTPUT_FORMAT
    public_key_path = settings.PUBLIC_KEY_PATH
    remove_unencrypted_files = settings.REMOVE_UNENCRYPTED_FILES

    sql_query_env = settings.SQL_QUERY
    database_table = settings.DATABASE_TABLE
    database_schema = settings.DATABASE_SCHEMA
    csv_encoding = settings.CSV_ENCODING
    csv_quoting_str = settings.CSV_QUOTING
    csv_date_format = settings.CSV_DATE_FORMAT
    date_columns = settings.DATE_COLUMNS

    # Map CSV_QUOTING string to csv module constants
    quoting_map = {
        'QUOTE_MINIMAL': csv.QUOTE_MINIMAL,
        'QUOTE_ALL': csv.QUOTE_ALL,
        'QUOTE_NONNUMERIC': csv.QUOTE_NONNUMERIC,
        'QUOTE_NONE': csv.QUOTE_NONE
    }
    csv_quoting = quoting_map.get(csv_quoting_str, csv.QUOTE_MINIMAL)

    # Validation and SQL Query Construction
    if not database_url:
        print("Error: DATABASE_URL environment variable not set. See README.md.", file=sys.stderr)
        return
    if not output_directory:
        print("Error: OUTPUT_DIRECTORY environment variable not set. See README.md.", file=sys.stderr)
        return
    if not db_index_column:
        print("Error: DB_INDEX_COLUMN environment variable not set. See README.md.", file=sys.stderr)
        return
    if output_format not in ['csv', 'parquet']:
        print(f"Error: Invalid OUTPUT_FORMAT '{output_format}'. Must be 'csv' or 'parquet'.", file=sys.stderr)
        return
    if public_key_path and not os.path.exists(public_key_path):
        print(f"Error: PUBLIC_KEY_PATH specified but file not found: {public_key_path}", file=sys.stderr)
        return

    if sql_query_env and database_table:
        print("Error: Both SQL_QUERY and DATABASE_TABLE are set. Specify only one. See README.md.", file=sys.stderr)
        return
    elif sql_query_env:
        sql_query = sql_query_env
        print("Using provided SQL_QUERY.")
    elif database_table:
        print(f"Using DATABASE_TABLE '{database_table}'.")
    else:
        print("Error: Neither SQL_QUERY nor DATABASE_TABLE is set. See README.md.", file=sys.stderr)
        return

    print(f"Database URL: {database_url}")
    print(f"Output Directory: {output_directory}")
    print(f"Database Index Column: {db_index_column}")
    print(f"Output Format: {output_format}")
    if public_key_path:
        print(f"Encryption enabled. Public Key Path: {public_key_path}")
        print(f"Remove unencrypted files after encryption: {remove_unencrypted_files}")
    if output_format == 'csv':
        print(f"CSV Encoding: {csv_encoding}")
        print(f"CSV Quoting: {csv_quoting_str} (mapped to {csv_quoting})")
        print(f"CSV Date Format: {csv_date_format if csv_date_format else 'pandas default'}")
    if date_columns:
        print(f"Date columns to convert: {date_columns}")

    engine = None
    try:
        # Connect to the database
        print("Attempting to connect to the database...")
        engine = create_engine(database_url)
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        
        print("Successfully connected to the database.")
        # Load data into Dask DataFrame
        print("Executing SQL query and loading data into Dask DataFrame...", database_url)
        if sql_query_env:
            #We need a selectable for Dask so hack the sql string
            sql_query = re.sub("^SELECT","",sql_query,flags = re.I)
            parts = re.split("WHeRE",sql_query,flags=re.I)
            sql_select = parts[0]
            if len(parts)>1:
                sql_where = parts[1]
                s = select(text(sql_select)).where(text(sql_where))
            else:
                s = select(text(sql_select))
            ddf = dd.read_sql_query(
                sql=s,
                con=database_url,
                index_col=db_index_column,
            )
        else:
            ddf = dd.read_sql_table(
                table_name=database_table,
                con=database_url,
                index_col=db_index_column,
                schema=database_schema,
            )

        # Convert specified columns to datetime objects
        if date_columns:
            print(f"Attempting to convert date columns: {date_columns}")
            for col in date_columns:
                if col in ddf.columns:
                    # errors='coerce' will turn unparseable values into NaT (Not a Time)
                    ddf[col] = dd.to_datetime(ddf[col], errors='coerce')
                    print(f"  - Column '{col}' conversion scheduled.")
                else:
                    print(f"Warning: Date column '{col}' specified in DATE_COLUMNS not found in the query result.", file=sys.stderr)

        print(f"Dask DataFrame created with {ddf.npartitions} partitions.")
        print("First 5 rows of the Dask DataFrame (computing head):")
        print(ddf.head())

        # Save data to specified file format
        output_paths = []
        if output_format == 'csv':
            print(f"Saving data to CSV files in directory: {output_directory}...",csv_date_format)
            output_paths = ddf.to_csv(
                os.path.join(output_directory, 'part_*.csv'),
                index=True,
                encoding=csv_encoding,
                quoting=csv_quoting,
                date_format=csv_date_format,
                single_file=False
            )
            print(f"Data successfully saved to CSV files in {output_directory}.")
        elif output_format == 'parquet':
            print(f"Saving data to Parquet files in directory: {output_directory}...")
            ddf.to_parquet(
                output_directory,
                engine='pyarrow',
                write_index=True,
            )
            print(f"Data successfully saved to Parquet files in {output_directory}.")
            output_paths = glob.glob(os.path.join(output_directory, '*.parquet'))

        # Encrypt files if public_key_path is provided
        if public_key_path:
            print("Starting encryption process...")
            if not output_paths:
                if output_format == 'csv':
                    output_paths = glob.glob(os.path.join(output_directory, '*.csv'))
                elif output_format == 'parquet':
                    output_paths = glob.glob(os.path.join(output_directory, '*.parquet'))

            if not output_paths:
                print("Warning: No files found to encrypt. Check output directory and format.", file=sys.stderr)
            else:
                for file_path in output_paths:
                    encrypt_file_with_public_key(file_path, public_key_path, remove_unencrypted_files)
                print("Encryption process completed.")

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        raise
    finally:
        if engine:
            engine.dispose()
            print("Database engine disposed.")

if __name__ == "__main__":
    extract_sql_to_file()
