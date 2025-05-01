#!/bin/bash
# Ensure exactly two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: ./tls_client.sh <server_IP> <server_PORT>"
    exit 1
fi
# Run the Python TLS client
python3 tls_client.py "$1" "$2"
