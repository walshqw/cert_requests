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

    const fqdn = document.getElementById('fqdn').value.trim();
    const sansInput = document.getElementById('sans').value.trim();
    const email = document.getElementById('email').value.trim();

    if (!fqdn) {
        statusElement.textContent = "Error: Please enter the Fully Qualified Domain Name (FQDN).";
        return;
    }

    try {
        // --- 1. Generate RSA Key Pair (Asynchronously) ---
        // This is the most CPU-intensive step.
        const kp = rsa.generateKeypair(2048);
        const privateKey = kp.prvKey;
        const publicKey = kp.pubKey;
        
        // Convert to PEM format
        const privateKeyPEM = rsa.KEYUTIL.getPEM(privateKey, 'PKCS8PRV');
        
        // --- 2. Build Subject DN and Extensions ---
        
        // Define Subject DN (Common Name, Email)
        const subject = [
            { name: 'commonName', value: fqdn },
        ];

        // Add email if provided
        if (email) {
            subject.push({ name: 'emailAddress', value: email });
        }

        // --- 3. Build Subject Alternative Names (SANs) Extension ---
        
        // Start the SAN list with the FQDN (CN) itself
        const sanList = [{ dns: fqdn }];
        
        if (sansInput) {
            const sansArray = sansInput.split(',').map(s => s.trim()).filter(s => s.length > 0);
            sansArray.forEach(domain => {
                sanList.push({ dns: domain });
            });
        }

        // Define the X.509 extensions for the CSR
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
            extreq: extensions, // Attach the SANs
            sigalg: 'SHA256withRSA',
            sbjpubkey: publicKey,
            privateKey: privateKey // Sign the CSR with the private key
        });

        // --- 5. Finalize and Get PEM ---
        const csrPEM = csr.getPEMString();
        
        // --- 6. Filename Generation (Replicating your bash script logic) ---
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