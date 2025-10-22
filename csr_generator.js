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
        // Get status element and display initial message
        statusElement.textContent = "Processing... Generating 2048-bit RSA key (this may take a few seconds).";
        statusElement.style.color = 'orange';

        // --- 1. Generate RSA Key Pair (Synchronous) ---
        
        // This generates the key pair object {prvKey: RSAKey, pubKey: RSAKey}
        const rsaKeypair = KEYUTIL.generateKeypair('RSA', 2048);
        
        // Access the private key (which is an RSAKey object)
        const privateKeyObj = rsaKeypair.prvKey;
        
        // **FIXED:** Get the private key PEM string. KEYUTIL.getPEM is the correct function.
        // It accepts the RSAKey object and the format string ('PKCS8PRV' for unencrypted).
        const privateKeyPEM = KEYUTIL.getPEM(privateKeyObj, 'PKCS8PRV');
        
        // --- 2. Build Subject DN using Hardcoded Values from CSR cfg ---
        const subject = [
            // Hardcoded DN Fields from your csr.cnf
            { name: 'countryName', value: 'US' },
            { name: 'stateOrProvinceName', value: 'MA' },
            { name: 'localityName', value: 'Boston' },
            { name: 'organizationName', value: 'Trustees of Boston College' },
            { name: 'organizationalUnitName', value: 'BC' },
            { name: 'emailAddress', value: 'itsstaff.ops@bc.edu' },
            { name: 'commonName', value: fqdn }, 
        ];

        // --- 3. Build Subject Alternative Names (SANs) Extension ---
        const sanList = [{ dns: fqdn }]; 
        
        if (sansInput) {
            const sansArray = sansInput.split(',').map(s => s.trim()).filter(s => s.length > 0);
            sansArray.forEach(domain => {
                sanList.push({ dns: domain });
            });
        }

        const extensions = [
            { extname: 'subjectAltName', array: sanList }
        ];

        // --- 4. Create CSR Object ---
        // We use the same privateKeyObj for both the public key in the CSR and for signing.
        const csr = new KJUR.asn1.csr.CertificationRequest({
            subject: subject,
            extreq: extensions, 
            sigalg: 'SHA256withRSA',
            sbjpubkey: privateKeyObj, // The privateKeyObj *is* the RSAKey object
            privateKey: privateKeyObj // Use the same object for signing
        });

        // --- 5. Finalize and Get PEM ---
        const csrPEM = csr.getPEMString();
        
        // --- 6. Filename Generation ---
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
        // ... (error handling) ...
        console.error("CSR Generation Error:", e);
        if (typeof KJUR === 'undefined' || typeof KEYUTIL === 'undefined') {
             statusElement.textContent = `CRITICAL ERROR: Cryptography library failed to load. Please try a hard refresh. (Check console for '${e.message}')`;
        } else {
            statusElement.textContent = `An error occurred during generation: ${e.message}. Please check the browser console for technical details.`;
        }
        statusElement.style.color = 'red';
    }
}