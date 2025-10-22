#!/bin/bash

# --- 1. Prompt for Inputs ---
echo "---------------------------------------------------------"
read -p "Enter the fully qualified domain name (FQDN) for the CN (e.g., server.bc.edu): " fqdn

echo ""
echo "Enter Subject Alternative Names (SANs), separated by commas."
read -p "Example: www.server.bc.edu,api.server.bc.edu (or leave blank for none): " sans_input

# --- 2. Build the Formatted SAN List ---
# The Common Name (CN) must always be the first SAN.
san_list_formatted="DNS.1 = ${fqdn}"
san_counter=2

if [ -n "$sans_input" ]; then
    # Convert comma-separated input into separate DNS entries
    IFS=',' read -r -a dns_array <<< "$sans_input"
    for domain in "${dns_array[@]}"; do
        domain=$(echo "$domain" | xargs) # Trim whitespace
        if [ "$domain" != "" ]; then
            san_list_formatted="${san_list_formatted}\nDNS.${san_counter} = ${domain}"
            ((san_counter++))
        fi
    done
fi

# --- 3. Set Environment Variable for CN and Define File Paths ---
export fqdn # CN still uses an environment variable
KEY_FILE="${fqdn%%.*}_$(date +%Y).key"
CSR_FILE="${fqdn%%.*}_$(date +%Y).csr"
TEMP_CONF="temp_csr.cnf" # Temporary configuration file

# --- 4. Generate the Final Configuration File ---
# Copy the template and append the generated SAN list.
cp csr.cnf "$TEMP_CONF"
echo -e "$san_list_formatted" >> "$TEMP_CONF"

# --- 5. Execute OpenSSL Command ---
echo ""
echo "Generating Private Key ($KEY_FILE) and CSR ($CSR_FILE)..."
echo "CN: $fqdn"
echo -e "SANs:\n$san_list_formatted"
echo "---------------------------------------------------------"

openssl req -new -newkey rsa:2048 -nodes \
-keyout "$KEY_FILE" -out "$CSR_FILE" \
-config "$TEMP_CONF" # Use the dynamically generated file!

# --- 6. Cleanup ---
unset fqdn
rm "$TEMP_CONF" # Remove the temporary configuration file

echo ""
echo "Process complete. CSR file ready for submission."