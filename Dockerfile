# Use a slim Python base image
FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y curl gnupg2 && \
    curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y msodbcsql18 && \
    # Clean up
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

#RUN groupadd -r xtract && useradd --no-log-init -r -g xtract xtract

#RUN mkdir /data && chown xtract:xtract /data
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sql_exporter.py .
COPY settings.py . 
COPY public_key.pem /app/keys/public_key.pem 

ENV OUTPUT_FORMAT="parquet"
ENV CSV_ENCODING="utf-8"
ENV CSV_QUOTING="QUOTE_MINIMAL"
ENV OUTPUT_DIRECTORY="/data"

#ENV CSV_DATE_FORMAT=""
ENV PUBLIC_KEY_PATH="/app/keys/public_key.pem"
ENV REMOVE_UNENCRYPTED_FILES="true"

# DATABASE_URL, DB_INDEX_COLUMN, and DATABASE_TABLE are expected to be provided at runtime

#TODO Need to find a neat way to handle the user perms on this folder. For now - run as root.
#USER xtract
CMD ["python", "sql_exporter.py"]
