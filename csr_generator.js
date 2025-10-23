// Helper function to trigger a file download (same as before)
function downloadFile(filename, content, type) {
    const blob = new Blob([content], { type: type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// Function to build the OpenSSL config string based on your .cnf file
function buildOpenSSLConfig(fqdn, sansInput) {
    let altNames = `DNS.1 = ${fqdn}\n`;
    let sanCounter = 2;

    if (sansInput) {
        // Convert comma-separated input into separate DNS entries
        const dnsArray = sansInput.split(',').map(s => s.trim()).filter(s => s.length > 0);
        for (const domain of dnsArray) {
            altNames += `DNS.${sanCounter} = ${domain}\n`;
            sanCounter++;
        }
    }

    // Template of your original csr.cnf file, injected with dynamic SANs
    const config = `
[ req ]
default_bits      = 2048
prompt            = no
default_md        = sha256
req_extensions    = v3_req
distinguished_name = dn_req

[ dn_req ]
C  = US
ST = MA
L  = Boston
O  = Trustees of Boston College
OU = BC
emailAddress = itsstaff.ops@bc.edu
CN = ${fqdn}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
${altNames}
    `;
    return config.trim();
}

/**
 * The main function to generate the CSR and Private Key using OpenSSL Wasm.
 */
async function generateCSR() {
    const statusElement = document.getElementById('status');
    statusElement.textContent = "Loading OpenSSL Wasm and Generating Key/CSR...";
    statusElement.style.color = 'orange';

    const fqdn = document.getElementById('fqdn').value.trim();
    const sansInput = document.getElementById('sans').value.trim();

    if (!fqdn) {
        statusElement.textContent = "Error: Please enter the FQDN.";
        statusElement.style.color = 'red';
        return;
    }

    try {
        // Initialize OpenSSL Wasm module
        // The 'OpenSSL' object is exposed globally by the CDN script in index.html
        if (typeof OpenSSL === 'undefined') {
        statusElement.textContent = "CRITICAL ERROR: OpenSSL Wasm library failed to load its main object. Please ensure the CDN link in index.html is correct and try a hard refresh.";
        statusElement.style.color = 'red';
        return; // Exit if the global object is not present
        }
        
        // Now, load the Wasm module itself
        const openssl = await OpenSSL.load();

        // 1. Build the dynamic config file content
        const configContent = buildOpenSSLConfig(fqdn, sansInput);
        
        // 2. Define filenames and paths
        const baseName = fqdn.split('.')[0];
        const dateString = new Date().getFullYear();
        const KEY_FILE = `${baseName}_${dateString}.key`;
        const CSR_FILE = `${baseName}_${dateString}.csr`;
        const TEMP_CONF = "temp_csr.cnf";

        // 3. Write config file to Wasm virtual filesystem (VFS)
        openssl.writeFile(TEMP_CONF, configContent);

        // 4. Execute the OpenSSL command via Wasm
        const command = [
            'req', '-new', '-newkey', 'rsa:2048', '-nodes', 
            '-keyout', KEY_FILE, 
            '-out', CSR_FILE,
            '-config', TEMP_CONF
        ];

        statusElement.textContent = "Executing OpenSSL command and generating files...";
        
        // This runs the compiled OpenSSL binary in the browser
        await openssl.run(command); 

        // 5. Read the generated files from the VFS
        const privateKeyPEM = openssl.readFile(KEY_FILE);
        const csrPEM = openssl.readFile(CSR_FILE);

        // 6. Clean up the VFS
        openssl.unlink(TEMP_CONF);
        openssl.unlink(KEY_FILE);
        openssl.unlink(CSR_FILE);

        // 7. Download Files
        downloadFile(KEY_FILE, privateKeyPEM, 'application/x-pem-file');
        downloadFile(CSR_FILE, csrPEM, 'application/x-pem-file');

        statusElement.textContent = "✅ Success! Key and CSR files downloaded. KEEP THE .KEY FILE SAFE!";
        statusElement.style.color = 'green';
        
    } catch (e) {
        console.error("CSR Generation Error:", e);
        statusElement.textContent = `A critical error occurred: ${e.message}. The OpenSSL process failed.`;
        statusElement.style.color = 'red';
    }
}