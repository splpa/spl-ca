#!/bin/bash
# Check if the correct number of arguments is given
if [ $# -ne 1 ]; then
  echo "Usage: $0 app"
  exit 1
fi

app=$1

# Check if the key file exists
if [ ! -f "./$app.key" ]; then
  openssl ecparam -genkey -name secp384r1 -out "./$app.key"
fi

# Check if the config file exists
if [ ! -f "./$app.cfg" ]; then
  echo "Please create openssl config file for $app"
  exit 1
else
  echo "Please verify the config file for $app and make sure the following is correct:"
  openssl req -new -key "./$app.key" -out "./$app.req" -config "./$app.cfg"
  echo "Please generate a new ssl cert with $app.req and copy $app.crt in this directory"
  echo "waiting for $app.crt"

  # Wait until the ./$app.crt file exists
  while [ ! -f "./$app.crt" ]; do
    sleep 1
  done

  openssl x509 -inform der -in "./$app.crt" -out "./$app.pem"
  echo "Congrats, the certificate has been made"
fi

# Prompt the user if they wish to clean up the old files
read -rp "Do you wish to clean up the old files? (y/n) " answer
case "${answer,,}" in
  y|yes)
    rm -f "./$app.crt" "./$app.req"
    echo "Old files have been cleaned up."
    ;;
  *)
    echo "No files have been deleted."
    ;;
esac
