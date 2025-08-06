SQL Data Extractor

This Python script uses Dask and SQLAlchemy to extract data from a SQL database and save it to either CSV or Parquet files. It also includes an option to encrypt the output files using a public key. It's designed to be run as a standalone script or within a Docker container, with configuration managed via environment variables.

Features

    Connects to various SQL databases using SQLAlchemy.

    Extracts data using either a direct SQL query or by specifying a table name (which generates a SELECT * query).

    Leverages Dask for efficient handling of large datasets.

    Outputs data to multiple CSV files or Parquet files within a specified directory.

    Configurable CSV output options: encoding, quoting, and date formatting.

    Optional Encryption: Encrypts output files using a hybrid encryption scheme (AES for data, RSA for the AES key) if a public key is provided. Encrypted files will have a .enc extension.

Prerequisites

    Python 3.9+

    Docker (if running in a container)

Setup

    Install dependencies:

    pip install -r requirements.txt

    Create .env file: Create a file named .env in the same directory as sql_exporter.py and settings.py. This file will hold your environment variables.

    DATABASE_URL="sqlite:///data/my_database.db"
    OUTPUT_DIRECTORY="output_data_dir/"
    DB_INDEX_COLUMN="id"
    OUTPUT_FORMAT="csv"
    DATABASE_TABLE="users"
    DATABASE_SCHEMA="cdm"
    # PUBLIC_KEY_PATH="/path/to/your/public_key.pem" # Uncomment and set if using encryption locally
    REMOVE_UNENCRYPTED_FILES="true"
    CSV_ENCODING="utf-8"
    CSV_QUOTING="QUOTE_MINIMAL"
    CSV_DATE_FORMAT="%Y-%m-%d %H:%M:%S"

Environment Variables

Settings are loaded from environment variables, prioritizing those set directly in the shell over those in the .env file.
Required Variables

    DATABASE_URL: The SQLAlchemy connection string for your database.

        Examples:

            SQLite: 'sqlite:///path/to/your_database.db'

            PostgreSQL: 'postgresql://user:password@host:port/database_name'

            MySQL: 'mysql+mysqlconnector://user:password@host:port/database_name'

    OUTPUT_DIRECTORY: The path to the directory where the output files (CSV or Parquet) will be saved. Dask writes multiple files into this directory.

        Example: 'output_data_dir/'

    DB_INDEX_COLUMN: The name of a column in your database table that Dask can use as an index. This is required by dask.dataframe.read_sql_query for efficient partitioning. Choose a column that is unique and preferably has an index in your database.

        Example: 'id', 'order_id'

    OUTPUT_FORMAT: The desired output file format.

        Possible values: 'csv' or 'parquet'

        Default: 'csv' (set in settings.py)

Data Selection

You must specify either SQL_QUERY or DATABASE_TABLE.

    SQL_QUERY: The full SQL statement to execute.
    N.B This is experimental and will only support SELECT ... WHERE ... statements. You should prefer a temp table and the DATABASE_TABLE option.

        Example: 'SELECT id, name, email FROM users WHERE status = "active";'

    DATABASE_TABLE: The name of a database table. If provided, the script will automatically generate a SELECT * FROM <table_name> query.

        Example: 'users'

    DATABASE_SCHEMA: The schema the table is in (or query should be run on).

        Example: 'public'

Optional Encryption Variables

    PUBLIC_KEY_PATH: (Optional) The absolute path to a PEM-encoded RSA public key file. If provided, all output files will be encrypted using this key.

        Example: '/path/to/your/public_key.pem' (when running locally)

        For Docker: If you include the public key in the Docker image (as shown in the Dockerfile below), this path will be internal to the container (e.g., "/app/keys/public_key.pem").

        How to generate a key pair (for testing/development):

        # Generate a private key
        openssl genrsa -out private_key.pem 2048
        # Extract the public key from the private key
        openssl rsa -in private_key.pem -pubout -out public_key.pem

        Decryption: To decrypt files, you'll need the corresponding private key and the decrypt_files.py script (see below).

    REMOVE_UNENCRYPTED_FILES: (Optional) A boolean flag ('true' or 'false') to control whether the original, unencrypted files are removed after successful encryption.

        Default: 'true' (original files are removed)

Optional CSV Formatting Variables (only applies if OUTPUT_FORMAT='csv')

    CSV_ENCODING: The character encoding for the CSV files.

        Default: 'utf-8' (set in settings.py)

        Examples: 'latin-1', 'cp1252'

    CSV_QUOTING: Controls when fields are quoted in the CSV output.

        Default: 'QUOTE_MINIMAL' (set in settings.py)

        Possible values (corresponding to Python's csv module constants):

            'QUOTE_MINIMAL'

            'QUOTE_ALL' (quotes all fields)

            'QUOTE_NONNUMERIC' (quotes all non-numeric fields)

            'QUOTE_NONE' (never quotes fields, can cause issues with special characters)

    CSV_DATE_FORMAT: A format string for datetime objects in the CSV output.

        Default: None (Dask/Pandas will use their default string representation for dates). N.B This will only be applied to database columns with a known DATE or DATETIME type.

        Examples: '%Y-%m-%d', '%Y-%m-%S %H:%M:%S'

How to Run sql_exporter.py
1. Locally (using .env file or environment variables)

The script will automatically load variables from the .env file. You can override them by setting environment variables directly in your shell.

## Linux/macOS:
```
OUTPUT_FORMAT="parquet" python sql_exporter.py
```
## Windows (Command Prompt):
```
set OUTPUT_FORMAT="parquet"
python sql_exporter.py
set OUTPUT_FORMAT= REM Unset the variable after use
```
## Windows (PowerShell):
```
$env:OUTPUT_FORMAT="parquet"
python sql_exporter.py
Remove-Item Env:\OUTPUT_FORMAT # Unset the variable after use
```
2. Using Docker for sql_exporter.py

First, set up required environment variables in the Dockerfile and then build the Docker image:

docker build -t sql-data-extractor .

Then, run the Docker container. You can override env vars by using the -e flag during docker run.

Linux/macOS:
```
mkdir output_data_dir # Create local directories

docker run -it --rm \
  -v "$(pwd)/output_data_dir:/data" \
  sql-data-extractor

# Example: Override OUTPUT_FORMAT to parquet at runtime
docker run -it --rm \
  -v "$(pwd)/output_data_dir:/data" \
  -e OUTPUT_FORMAT="parquet" \
  sql-data-extractor
```
Windows (Command Prompt):
```
REM Example: Run using settings from .env inside the container
mkdir data output_data_dir

docker run -it --rm ^
  -v "%cd%\output_data_dir:/data" ^
  sql-data-extractor

REM Example: Override OUTPUT_FORMAT to parquet at runtime
docker run -it --rm ^
  -v "%cd%\output_data_dir:/data" ^
  -e OUTPUT_FORMAT="parquet" ^
  sql-data-extractor
```
Windows (PowerShell):
```
New-Item -ItemType Directory -Force -Path ".\output_data_dir"

docker run -it --rm `
  -v "${PWD}/output_data_dir:/data" `
  sql-data-extractor

# Example: Override OUTPUT_FORMAT to parquet at runtime
docker run -it --rm `
  -v "${PWD}/output_data_dir:/data" `
  -e OUTPUT_FORMAT="parquet" `
  sql-data-extractor
```
After execution, the output files (encrypted or unencrypted, CSV or Parquet) will be found in the specified local output directory.

How to Run decrypt_files.py

This script is used to decrypt the files generated by sql_exporter.py when encryption was enabled.
Environment Variables for Decryption

    PRIVATE_KEY_PATH: The absolute path to your PEM-encoded RSA private key file. This key must correspond to the public key used for encryption.

        Example: '/path/to/your/private_key.pem'

    ENCRYPTED_INPUT_PATH: The path to the encrypted file or directory containing encrypted files (.enc extension). If it's a directory, the script will attempt to decrypt all .enc files within it.

        Example: '/path/to/encrypted_output_dir/' or '/path/to/encrypted_output_dir/part_0.csv.enc'

1. Locally (using environment variables)

Set the environment variables in your terminal before running the script.

Linux/macOS:

```
# Example for decrypting files
export PRIVATE_KEY_PATH='/path/to/your/private_key.pem'
export ENCRYPTED_INPUT_PATH='output_users_encrypted_csv/' # Or a specific file like 'output_users_encrypted_csv/part_0.csv.enc'

python decrypt_files.py
```
Windows (Command Prompt):
```
REM Example for decrypting files
set PRIVATE_KEY_PATH=C:\path\to\your\private_key.pem
set ENCRYPTED_INPUT_PATH=output_users_encrypted_csv\ REM Or a specific file like 'output_users_encrypted_csv\part_0.csv.enc'

python decrypt_files.py
```
Windows (PowerShell):
```
# Example for decrypting files
$env:PRIVATE_KEY_PATH='C:\path\to\your\private_key.pem'
$env:ENCRYPTED_INPUT_PATH='output_users_encrypted_csv/' # Or a specific file like 'output_users_encrypted_csv/part_0.csv.enc'

python decrypt_files.py
```
2. Using Docker for decrypt_files.py

First, build the Docker image for the decryption script:

docker build -f Dockerfile.decrypt -t file-decryptor .

Then, run the Docker container, providing the necessary environment variables and mounting volumes for key access and encrypted/decrypted files.

Linux/macOS:
```
# Example for decrypting files from a directory
mkdir -p decrypted_output # Directory for decrypted files
# (Place your private_key.pem in the 'keys' directory, and encrypted files in 'output_users_encrypted_csv')

docker run -it --rm \
  -v "$(pwd)/keys:/app/keys" \
  -v "$(pwd)/output_users_encrypted_csv:/app/encrypted_input" \
  -v "$(pwd)/decrypted_output:/app/decrypted_output" \
  -e PRIVATE_KEY_PATH="/app/keys/private_key.pem" \
  -e ENCRYPTED_INPUT_PATH="/app/encrypted_input" \
  file-decryptor
```
Windows (Command Prompt):
```
REM Example for decrypting files from a directory
mkdir decrypted_output
REM (Place your private_key.pem in the 'keys' directory, and encrypted files in 'output_users_encrypted_csv')

docker run -it --rm ^
  -v "%cd%\keys:/app/keys" ^
  -v "%cd%\output_users_encrypted_csv:/app/encrypted_input" ^
  -v "%cd%\decrypted_output:/app/decrypted_output" ^
  -e PRIVATE_KEY_PATH="/app/keys/private_key.pem" ^
  -e ENCRYPTED_INPUT_PATH="/app/encrypted_input" ^
  file-decryptor
```
Windows (PowerShell):
```
# Example for decrypting files from a directory
New-Item -ItemType Directory -Force -Path ".\decrypted_output"
# (Place your private_key.pem in the 'keys' directory, and encrypted files in 'output_users_encrypted_csv')

docker run -it --rm `
  -v "${PWD}/keys:/app/keys" `
  -v "${PWD}/output_users_encrypted_csv:/app/encrypted_input" `
  -v "${PWD}/decrypted_output:/app/decrypted_output" `
  -e PRIVATE_KEY_PATH="/app/keys/private_key.pem" `
  -e ENCRYPTED_INPUT_PATH="/app/encrypted_input" `
  file-decryptor
```
After decryption, the original (unencrypted) files will be created in the same directory as the encrypted files, or in the decrypted_output directory if you're using Docker and mapping a separate output volume.