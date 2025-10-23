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
 * The main function to generate the CSR and Private Key using Forge.
 */
async function generateCSR() {
    const statusElement = document.getElementById('status');
    statusElement.textContent = "Generating 2048-bit RSA key. This may take a moment...";
    statusElement.style.color = 'orange';

    // *** CRITICAL CHECK FOR LOCAL FILE SUCCESS ***
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
        // --- 1. Generate RSA Key Pair (Asynchronous) ---
        statusElement.textContent = "Step 1/5: Generating 2048-bit RSA key pair...";
        const keys = await new Promise((resolve, reject) => {
            // Use forge's built-in workers for non-blocking key generation
            forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keypair) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(keypair);
                }
            });
        });

        // --- 2. Create the CSR object ---
        statusElement.textContent = "Step 2/5: Creating Certification Request object...";
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keys.publicKey;

        // --- 3. Build Subject DN and SANs ---
        statusElement.textContent = "Step 3/5: Adding Subject Distinguished Name (DN) and SANs...";
        csr.subject.add('C', 'US');
        csr.subject.add('ST', 'MA');
        csr.subject.add('L', 'Boston');
        csr.subject.add('O', 'Trustees of Boston College');
        csr.subject.add('OU', 'BC');
        csr.subject.add('E', 'itsstaff.ops@bc.edu');
        csr.subject.add('CN', fqdn);

        // Build Subject Alternative Names (SANs)
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

        // Add the SANs extension to the CSR attributes
        csr.setAttributes([{
            name: 'extensionRequest',
            extensions: [{
                name: 'subjectAltName',
                altNames: altNamesArray
            }]
        }]);

        // --- 4. Sign the CSR ---
        statusElement.textContent = "Step 4/5: Signing the CSR with the private key...";
        await new Promise((resolve, reject) => {
            csr.sign(keys.privateKey, forge.md.sha256.create(), (err) => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });

        // --- 5. Encode Files and Download ---
        statusElement.textContent = "Step 5/5: Encoding and downloading files...";
        const privateKeyPEM = forge.pki.privateKeyToPem(keys.privateKey);
        const csrPEM = forge.pki.certificationRequestToPem(csr);
        
        // Filename Generation
        const baseName = fqdn.split('.')[0];
        const dateString = new Date().getFullYear();
        const KEY_FILE = `${baseName}_${dateString}.key`;
        const CSR_FILE = `${baseName}_${dateString}.csr`;

        // Download Files
        downloadFile(KEY_FILE, privateKeyPEM, 'application/x-pem-file');
        downloadFile(CSR_FILE, csrPEM, 'application/x-pem-file');

        statusElement.textContent = "✅ Success! Key and CSR files downloaded. KEEP THE .KEY FILE SAFE!";
        statusElement.style.color = 'green';
        
    } catch (e) {
        console.error("CSR Generation Error:", e);
        statusElement.textContent = `A critical error occurred: ${e.message}. The cryptography process failed.`;
        statusElement.style.color = 'red';
    }
}