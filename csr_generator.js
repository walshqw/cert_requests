/**
 * Helper function to trigger a file download. (NO CHANGE)
 * ...
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
 * The main function to generate the CSR and Private Key using Forge.
 */
async function generateCSR() {
    const statusElement = document.getElementById('status');
    const outputDiv = document.getElementById('csr-output');
    const csrTextarea = document.getElementById('csr-text');
    
    // Reset previous outputs
    outputDiv.style.display = 'none';
    csrTextarea.value = '';

    statusElement.textContent = "Generating 2048-bit RSA key. This may take a moment...";
    statusElement.style.color = 'orange';

    if (typeof forge === 'undefined' || !forge.pki) {
        statusElement.textContent = "CRITICAL ERROR: The local forge.min.js library failed to load. Please ensure the 'forge.min.js' file is in the same folder as index.html.";
        statusElement.style.color = 'red';
        return;
    }

    const fqdn = document.getElementById('fqdn').value.trim();
    const sansInput = document.getElementById('sans').value.trim();

    if (!fqdn) {
        statusElement.textContent = "Error: Please enter the FQDN.";
        statusElement.style.color = 'red';
        return;
    }

    try {
        // --- 1. Generate RSA Key Pair (SYNCHRONOUS) ---
        statusElement.textContent = "Step 1/4: Generating 2048-bit RSA key pair (Briefly freezing the page)...";
        const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
        
        // --- 2. Create the CSR object and Set Attributes ---
        statusElement.textContent = "Step 2/4: Creating CSR object and setting attributes...";
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keys.publicKey;
        
        const subjectAttributes = [
            { name: 'countryName', value: 'US' },
            { name: 'stateOrProvinceName', value: 'MA' },
            { name: 'localityName', value: 'Boston' },
            { name: 'organizationName', value: 'Trustees of Boston College' },
            { name: 'organizationalUnitName', value: 'BC' },
            { name: 'emailAddress', value: 'itsstaff.ops@bc.edu' },
            { name: 'commonName', value: fqdn }
        ];
        csr.setSubject(subjectAttributes);

        let altNamesArray = [{ type: 2, value: fqdn }];
        if (sansInput) {
            const dnsArray = sansInput.split(',').map(s => s.trim()).filter(s => s.length > 0);
            dnsArray.forEach(domain => {
                altNamesArray.push({ type: 2, value: domain });
            });
        }
        csr.setAttributes([{
            name: 'extensionRequest',
            extensions: [{ name: 'subjectAltName', altNames: altNamesArray }]
        }]);

        // --- 3. Sign the CSR (SYNCHRONOUS) ---
        statusElement.textContent = "Step 3/4: Signing the CSR with the private key...";
        csr.sign(keys.privateKey, forge.md.sha256.create());

        // --- 4. Encode, Download KEY, and Display CSR ---
        statusElement.textContent = "Step 4/4: Encoding files and preparing download/output...";
        const privateKeyPEM = forge.pki.privateKeyToPem(keys.privateKey);
        const csrPEM = forge.pki.certificationRequestToPem(csr);
        
        // Filename Generation
        const baseName = fqdn.split('.')[0];
        const dateString = new Date().getFullYear();
        const KEY_FILE = `${baseName}_${dateString}.key`;
        
        // **ACTION 1: Download Private Key (Always works)**
        downloadFile(KEY_FILE, privateKeyPEM, 'application/x-pem-file');
        
        // **ACTION 2: Display CSR (Bypasses second download block)**
        csrTextarea.value = csrPEM;
        outputDiv.style.display = 'block';
        csrTextarea.focus();
        csrTextarea.select(); // Auto-select the text for easy copying

        statusElement.textContent = "✅ Success! Key file downloaded. Copy the CSR text below. KEEP THE .KEY FILE SAFE!  It should be saved on the server with the certificate and deleted from your computer!";
        statusElement.style.color = 'green';
        
    } catch (e) {
        console.error("CSR Generation Error:", e);
        statusElement.textContent = `A critical error occurred: ${e.message}. The cryptography process failed.`;
        statusElement.style.color = 'red';
    }
}