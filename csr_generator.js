/**
 * Helper function to trigger a file download.
 * @param {string} filename - The name of the file to save.
 * @param {string} content - The content of the file (e.g., PEM string).
 * @param {string} type - The MIME type.
 */
function downloadFile(filename, content, type) {
    const blob = new Blob([content], { type: type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

/**
 * The main function to generate the CSR and Private Key.
 */
function generateCSR() {
    // Get status element and display initial message
    const statusElement = document.getElementById('status');
    statusElement.textContent = "Processing... Generating 2048-bit RSA key (this may take a few seconds).";
    statusElement.style.color = 'orange';

    // Get user inputs
    const fqdn = document.getElementById('fqdn').value.trim();
    const sansInput = document.getElementById('sans').value.trim();

    // Input validation
    if (!fqdn) {
        statusElement.textContent = "Error: Please enter the Fully Qualified Domain Name (FQDN).";
        statusElement.style.color = 'red';
        return;
    }

    try {
        // --- 1. Generate RSA Key Pair (Synchronous) ---
        
        // **FIXED:** Use the KEYUTIL object from the global namespace for key generation
        // This is the most reliable way to generate keys with the jsrsasign library.
        const rsaKey = KEYUTIL.generateKeypair('RSA', 2048);
        
        // Extract the private key object from the generated pair
        const privateKeyObj = rsaKey.prvKey;
        
        // Get the private key and convert it to PKCS#8 PEM format
        const privateKeyPEM = KEYUTIL.getPEM(privateKeyObj, 'PKCS8PRV');
        
        // --- 2. Build Subject DN using Hardcoded Values from CSR cfg ---
        // This array matches the fields in your [ dn_req ] section
        const subject = [
            // Hardcoded DN Fields from your csr.cnf
            { name: 'countryName', value: 'US' },
            { name: 'stateOrProvinceName', value: 'MA' },
            { name: 'localityName', value: 'Boston' },
            { name: 'organizationName', value: 'Trustees of Boston College' },
            { name: 'organizationalUnitName', value: 'BC' },
            { name: 'emailAddress', value: 'itsstaff.ops@bc.edu' },

            // Common Name (CN) - Read from user input
            { name: 'commonName', value: fqdn }, 
        ];

        // --- 3. Build Subject Alternative Names (SANs) Extension ---
        // The Common Name (CN) is always the first SAN
        const sanList = [{ dns: fqdn }]; 
        
        if (sansInput) {
            const sansArray = sansInput.split(',').map(s => s.trim()).filter(s => s.length > 0);
            sansArray.forEach(domain => {
                sanList.push({ dns: domain });
            });
        }

        // Define the X.509 extensions for the CSR
        const extensions = [
            { 
                extname: 'subjectAltName', 
                array: sanList 
            }
        ];

        // --- 4. Create CSR Object ---
        // Use the KJUR namespace for the CertificationRequest class
        const csr = new KJUR.asn1.csr.CertificationRequest({
            subject: subject,
            extreq: extensions, 
            sigalg: 'SHA256withRSA',
            sbjpubkey: privateKeyObj, // Use the generated key object for the public key
            privateKey: privateKeyObj // Use the generated key object to sign the CSR
        });

        // --- 5. Finalize and Get PEM ---
        const csrPEM = csr.getPEMString();
        
        // --- 6. Filename Generation ---
        // Match the naming convention from your bash script: baseName_year
        const baseName = fqdn.split('.')[0];
        const dateString = new Date().getFullYear();
        const keyFileName = `${baseName}_${dateString}.key`;
        const csrFileName = `${baseName}_${dateString}.csr`;

        // --- 7. Download Files ---
        downloadFile(keyFileName, privateKeyPEM, 'application/x-pem-file');
        downloadFile(csrFileName, csrPEM, 'application/x-pem-file');

        statusElement.textContent = "✅ Success! Key and CSR files downloaded. KEEP THE .KEY FILE SAFE!";
        statusElement.style.color = 'green';
        
    } catch (e) {
        console.error("CSR Generation Error:", e);
        // Fallback check to guide the user if library objects are still missing
        if (typeof KJUR === 'undefined' || typeof KEYUTIL === 'undefined') {
             statusElement.textContent = `CRITICAL ERROR: Cryptography library failed to load. Please try a hard refresh. (Check console for '${e.message}')`;
        } else {
            statusElement.textContent = `An error occurred during generation: ${e.message}. Please check the browser console for technical details.`;
        }
        statusElement.style.color = 'red';
    }
}