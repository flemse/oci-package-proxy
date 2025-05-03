#!/bin/bash

CERT_FILE="tmp/cert.pem"

if [ ! -f "$CERT_FILE" ]; then
  echo "Certificate file $CERT_FILE not found!"
  exit 1
fi

echo "Adding $CERT_FILE to the macOS System Keychain..."
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_FILE"

if [ $? -eq 0 ]; then
  echo "Certificate successfully added and trusted."

  # Restart the trustd service to reload certificates
  echo "Reloading macOS trust settings..."
  sudo pkill -HUP trustd

  echo "Certificate installation and reload complete."
else
  echo "Failed to add the certificate to the System Keychain."
  exit 1
fi
