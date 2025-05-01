import socket  # Import socket module for network communication
import ssl  # Import SSL module for secure connection
import sys  # Import sys module for command-line argument handling
import datetime  # Import datetime for handling expiration dates
import pytz  # Import pytz for timezone-aware datetime handling

# Ensure correct number of arguments
if len(sys.argv) != 3:  # Checks if the number of arguments is not exactly 3
    print("Usage: python3 tls_client.py <server_IP> <server_PORT>")
    sys.exit(1)  # Exit the program with an error code

# Retrieve command-line arguments
server_ip = sys.argv[1]  # The first argument is the server IP
server_port = int(sys.argv[2])  # The second argument is the server port (convert to int)

# Define the path to the provided root CA certificate
ca_cert_path = "root_certificate.crt.pem"  # Use your actual root CA file

try:
    # Create a TCP connection to the server
    sock = socket.create_connection((server_ip, server_port))

    # Set up TLS context with root CA
    context = ssl.create_default_context(cafile=ca_cert_path)
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2 or higher
    context.check_hostname = False  # Disable hostname verification

    # Wrap socket in SSL/TLS
    tls_conn = context.wrap_socket(sock, server_hostname=server_ip)

    # Get server certificate
    cert = tls_conn.getpeercert()

    # Check if the certificate is available
    if not cert:
        print("Requirement 1 not met.", file=sys.stderr)
        sys.exit(1)

    # Check if the certificate is expired
    if "notAfter" in cert:
        expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        expiry_date = expiry_date.replace(tzinfo=pytz.UTC)  # Convert to timezone-aware datetime
        # Compare expiration date with current UTC time
        if expiry_date < datetime.datetime.now(pytz.UTC):
            print("Requirement 2 not met.", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Certificate does not contain 'notAfter' field.", file=sys.stderr)
        sys.exit(1)

    # Check forward secrecy (TLS 1.2 with ECDHE/DHE key exchange)
    cipher = tls_conn.cipher()[0]  # Get the cipher suite used in the connection
    if "ECDHE" not in cipher and "DHE" not in cipher:
        print("Requirement 3 not met.", file=sys.stderr)
        sys.exit(1)

    # Send a message to the server
    tls_conn.sendall(b"Hello, Server!")

    # Receive response
    response = tls_conn.recv(1024)
    print(response.decode())  # Print the server's response

    # Close the TLS connection
    tls_conn.close()

except ssl.SSLCertVerificationError as e:  # Handle certificate verification errors
    if e.verify_code == 10:  # Expired certificate error (X509_V_ERR_CERT_HAS_EXPIRED)
        print("Requirement 2 not met.", file=sys.stderr)
    else:
        print("Requirement 1 not met.", file=sys.stderr)  # Any other certificate verification failure
    sys.exit(1)

except ssl.SSLError as e:  # Handle other SSL errors
    print("TLS Error:", e, file=sys.stderr)
    sys.exit(1)

except Exception as e:  # Handle all other unexpected errors
    print("Error:", e, file=sys.stderr)
    sys.exit(1)
