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
    const statusElement = document.getElementById('status');
    statusElement.textContent = "Processing... Generating 2048-bit RSA key. This may take a moment.";
    statusElement.style.color = 'orange';

    const fqdn = document.getElementById('fqdn').value.trim();
    const sansInput = document.getElementById('sans').value.trim();
    // Note: The user-provided email input is no longer used, 
    // as it is now hardcoded as per the .cnf file.

    if (!fqdn) {
        statusElement.textContent = "Error: Please enter the Fully Qualified Domain Name (FQDN).";
        statusElement.style.color = 'red';
        return;
    }

    try {
        // --- 1. Generate RSA Key Pair (Asynchronously) ---
        const kp = rsa.generateKeypair(2048);
        const privateKey = kp.prvKey;
        const publicKey = kp.pubKey;
        const privateKeyPEM = rsa.KEYUTIL.getPEM(privateKey, 'PKCS8PRV');
        
        // --- 2. Build Subject DN using Hardcoded Values from CSR cfg ---
        // This array now matches the fields in your [ dn_req ] section
        const subject = [
            // Hardcoded DN Fields
            { name: 'countryName', value: 'US' },     // C = US
            { name: 'stateOrProvinceName', value: 'MA' }, // ST = MA
            { name: 'localityName', value: 'Boston' },   // L = Boston
            { name: 'organizationName', value: 'Trustees of Boston College' }, // O = Trustees of Boston College
            { name: 'organizationalUnitName', value: 'BC' }, // OU = BC
            { name: 'emailAddress', value: 'itsstaff.ops@bc.edu' }, // Hardcoded Email Address

            // Common Name (CN) - Read from user input, matching CN = $ENV::fqdn
            { name: 'commonName', value: fqdn }, 
        ];

        // --- 3. Build Subject Alternative Names (SANs) Extension ---
        const sanList = [{ dns: fqdn }]; // CN is always the first SAN
        
        if (sansInput) {
            const sansArray = sansInput.split(',').map(s => s.trim()).filter(s => s.length > 0);
            sansArray.forEach(domain => {
                sanList.push({ dns: domain });
            });
        }

        const extensions = [
            // The Subject Alternative Name (SAN) extension
            { 
                extname: 'subjectAltName', 
                array: sanList 
            }
        ];

        // --- 4. Create CSR Object ---
        const csr = new rsa.KJUR.asn1.csr.CertificationRequest({
            subject: subject,
            extreq: extensions, 
            sigalg: 'SHA256withRSA',
            sbjpubkey: publicKey,
            privateKey: privateKey
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
        console.error("CSR Generation Error:", e);
        statusElement.textContent = `An error occurred during generation: ${e.message}. Check the browser console for details.`;
        statusElement.style.color = 'red';
    }
}