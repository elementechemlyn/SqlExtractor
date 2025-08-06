import os
from dotenv import load_dotenv

# Load environment variables from .env file
# This should be called at the very beginning of your application
load_dotenv()

class Settings:
    """
    Manages application settings loaded from environment variables.
    Detailed descriptions for each setting are in README.md.
    """
    # Database and Output Configuration
    DATABASE_URL: str = os.getenv('DATABASE_URL')
    OUTPUT_DIRECTORY: str = os.getenv('OUTPUT_DIRECTORY')
    DB_INDEX_COLUMN: str = os.getenv('DB_INDEX_COLUMN')
    OUTPUT_FORMAT: str = os.getenv('OUTPUT_FORMAT', 'csv').lower()

    # Data Selection (choose one)
    SQL_QUERY: str = os.getenv('SQL_QUERY')
    DATABASE_TABLE: str = os.getenv('DATABASE_TABLE')
    DATABASE_SCHEMA: str = os.getenv('DATABASE_SCHEMA')

    # Encryption Settings
    PUBLIC_KEY_PATH: str = os.getenv('PUBLIC_KEY_PATH')
    REMOVE_UNENCRYPTED_FILES: bool = os.getenv('REMOVE_UNENCRYPTED_FILES', 'true').lower() == 'true'

    # CSV Formatting Settings (only applies if OUTPUT_FORMAT='csv')
    CSV_ENCODING: str = os.getenv('CSV_ENCODING', 'utf-8')
    CSV_QUOTING: str = os.getenv('CSV_QUOTING', 'QUOTE_MINIMAL')
    CSV_DATE_FORMAT: str = os.getenv('CSV_DATE_FORMAT') # None by default. Only needed if the db doesn't have a date type (i.e sqlite)

    # Date Column Conversion
    _date_columns_env = os.getenv('DATE_COLUMNS')
    DATE_COLUMNS: list[str] = [col.strip() for col in _date_columns_env.split(',')] if _date_columns_env else []

# Instantiate settings to be imported by other modules
settings = Settings()

if __name__ == "__main__":
    # This block is for testing/debugging the settings loading
    print("--- Loaded Settings ---")
    for attr in dir(settings):
        if not attr.startswith('__') and not callable(getattr(settings, attr)):
            print(f"{attr}: {getattr(settings, attr)}")
    print("-----------------------")
