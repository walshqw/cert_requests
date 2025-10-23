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
        // --- 1. Generate RSA Key Pair (SYNCHRONOUS FIX) ---
        statusElement.textContent = "Step 1/5: Generating 2048-bit RSA key pair (This may briefly freeze the page)...";
        
        // **FIX:** Use the SYNCHRONOUS version of generateKeyPair.
        // This eliminates Web Worker issues entirely. It WILL briefly freeze the UI.
        const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 }); // Using common exponent
        
        // The synchronous version of generateKeyPair returns the keypair object directly.

        // --- 2. Create the CSR object ---
        statusElement.textContent = "Step 2/5: Creating Certification Request object...";
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keys.publicKey;

        // --- 3. Build Subject DN and SANs ---
        statusElement.textContent = "Step 3/5: Adding Subject Distinguished Name (DN) and SANs...";
        
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

        let altNamesArray = [{
            type: 2, // dNSName
            value: fqdn
        }];
        
        if (sansInput) {
            const dnsArray = sansInput.split(',').map(s => s.trim()).filter(s => s.length > 0);
            dnsArray.forEach(domain => {
                altNamesArray.push({ type: 2, value: domain });
            });
        }

        csr.setAttributes([{
            name: 'extensionRequest',
            extensions: [{
                name: 'subjectAltName',
                altNames: altNamesArray
            }]
        }]);

        // --- 4. Sign the CSR (SYNCHRONOUS FIX) ---
        statusElement.textContent = "Step 4/5: Signing the CSR with the private key (This is fast, but may require a moment of UI unresponsiveness)...";
        
        // **FIX:** The synchronous key generation means the synchronous sign method works reliably.
        csr.sign(keys.privateKey, forge.md.sha256.create());
        // No promise or callback is needed for the synchronous sign function.


        // --- 5. Encode Files and Download ---
        statusElement.textContent = "Step 5/5: Encoding and downloading files...";
        const privateKeyPEM = forge.pki.privateKeyToPem(keys.privateKey);
        const csrPEM = forge.pki.certificationRequestToPem(csr);
        
        // Filename Generation
        const baseName = fqdn.split('.')[0];
        const dateString = new Date().getFullYear();
        const KEY_FILE = `${baseName}_${dateString}.key`;
        const CSR_FILE = `${baseName}_${dateString}.csr`;

        // Download 1: Private Key
        downloadFile(KEY_FILE, privateKeyPEM, 'application/x-pem-file');
        
        // Add a small delay (100ms) before the second download
        // This prevents the browser from blocking one download or URL object
        await new Promise(resolve => setTimeout(resolve, 100)); 

        // Download 2: CSR File
        downloadFile(CSR_FILE, csrPEM, 'application/x-pem-file');

        statusElement.textContent = "✅ Success! Key and CSR files downloaded. KEEP THE .KEY FILE SAFE!";
        statusElement.style.color = 'green';
        
    } catch (e) {
        console.error("CSR Generation Error:", e);
        statusElement.textContent = `A critical error occurred: ${e.message}. The cryptography process failed.`;
        statusElement.style.color = 'red';
    }
}