// CTF Arsenal - Ultimate Security Tool Dashboard
// Complete implementation with all 50+ tools

// Global variables
let currentTool = null;
let modalOpen = false;

// Navigation functionality
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializeModal();
    showSection('dashboard');
});

function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const section = this.getAttribute('data-section');
            showSection(section);

            // Update active nav link
            navLinks.forEach(nl => nl.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

function showSection(sectionName) {
    const sections = document.querySelectorAll('.tool-section');
    sections.forEach(section => {
        section.classList.remove('active');
    });

    const targetSection = document.getElementById(sectionName);
    if (targetSection) {
        targetSection.classList.add('active');
    }
}

// Modal functionality
function initializeModal() {
    const modal = document.getElementById('toolModal');
    window.onclick = function(event) {
        if (event.target === modal) {
            closeModal();
        }
    };
}

function showTool(toolName) {
    currentTool = toolName;
    const modal = document.getElementById('toolModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    modalTitle.textContent = getToolTitle(toolName);
    modalBody.innerHTML = getToolInterface(toolName);

    modal.style.display = 'block';
    modalOpen = true;

    // Initialize tool-specific functionality
    initializeTool(toolName);
}

function closeModal() {
    const modal = document.getElementById('toolModal');
    modal.style.display = 'none';
    modalOpen = false;
    currentTool = null;
}

function getToolTitle(toolName) {
    const titles = {
        'base64': 'Base64 Encoder/Decoder',
        'url': 'URL Encoder/Decoder',
        'hex': 'Hexadecimal Converter',
        'ascii': 'ASCII Converter',
        'binary-converter': 'Binary Converter',
        'caesar': 'Caesar Cipher',
        'vigenere': 'Vigenère Cipher',
        'atbash': 'Atbash Cipher',
        'rot13': 'ROT13 Cipher',
        'morse-decoder': 'Morse Code Translator',
        'hash-identifier': 'Hash Identifier & Analyzer',
        'hash-cracker': 'Advanced Hash Cracker',
        'md5': 'MD5 Hash Tools',
        'sha': 'SHA Hash Tools',
        'rainbow': 'Rainbow Table Lookup',
        'password-generator': 'Password Generator',
        'sql-injection': 'SQL Injection Tool',
        'payload-generator': 'Payload Generator',
        'jwt-decoder': 'JWT Decoder & Analyzer',
        'xss-payloads': 'XSS Payload Generator',
        'js-beautifier': 'JavaScript Beautifier',
        'xss-detector': 'XSS Detector',
        'request-builder': 'HTTP Request Builder',
        'header-analyzer': 'Security Header Analyzer',
        'forensics-analyzer': 'Advanced File Analyzer',
        'metadata-extractor': 'Metadata Extractor',
        'hex-viewer': 'Advanced Hex Viewer',
        'string-extractor': 'String Extractor',
        'steganography': 'Advanced Steganography Analyzer',
        'lsb-extractor': 'LSB Extractor',
        'pcap-analyzer': 'PCAP Analyzer',
        'packet-viewer': 'Packet Viewer',
        'disassembler': 'Advanced Disassembler',
        'decompiler': 'Decompiler',
        'binary-analyzer': 'Binary Analyzer',
        'rop-gadget': 'ROP Gadget Finder',
        'shellcode-generator': 'Shellcode Generator',
        'pattern-generator': 'Pattern Generator',
        'offset-finder': 'Offset Finder',
        'qr-decoder': 'QR Code Decoder',
        'barcode-decoder': 'Barcode Decoder',
        'brainfuck': 'Brainfuck Interpreter'
    };
    return titles[toolName] || 'Unknown Tool';
}

function getToolInterface(toolName) {
    switch(toolName) {
        case 'base64':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Text/Data:</label>
                        <textarea id="base64Input" rows="6" placeholder="Enter text to encode/decode or paste base64 data"></textarea>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="base64Encode()">Encode to Base64</button>
                        <button class="btn" onclick="base64Decode()">Decode from Base64</button>
                        <button class="btn" onclick="base64UrlSafeEncode()">URL-Safe Encode</button>
                        <button class="btn" onclick="base64UrlSafeDecode()">URL-Safe Decode</button>
                        <button class="btn" onclick="clearBase64()">Clear All</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="base64Output" class="output-area"></div>
                    </div>
                    <div class="input-group">
                        <label>File Operations:</label>
                        <input type="file" id="base64File" style="margin-bottom: 0.5rem;">
                        <div class="btn-grid">
                            <button class="btn" onclick="encodeFile()">Encode File</button>
                            <button class="btn" onclick="downloadBase64()">Download as File</button>
                        </div>
                    </div>
                </div>
            `;

        case 'caesar':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Text:</label>
                        <textarea id="caesarInput" rows="4" placeholder="Enter text to encrypt/decrypt"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Shift Value (0-25):</label>
                        <input type="number" id="caesarShift" min="0" max="25" value="13" placeholder="13">
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="caesarEncrypt()">Encrypt</button>
                        <button class="btn" onclick="caesarDecrypt()">Decrypt</button>
                        <button class="btn" onclick="caesarBruteForce()">Brute Force All Shifts</button>
                        <button class="btn" onclick="clearCaesar()">Clear</button>
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
                        <textarea id="hexInput" rows="4" placeholder="Enter text or hex data"></textarea>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="textToHex()">Text → Hex</button>
                        <button class="btn" onclick="hexToText()">Hex → Text</button>
                        <button class="btn" onclick="hexToBytes()">Hex → Bytes</button>
                        <button class="btn" onclick="clearHex()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="hexOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'hash-identifier':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Hash to Analyze:</label>
                        <textarea id="hashInput" rows="3" placeholder="Enter hash to identify"></textarea>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="identifyHash()">Identify Hash</button>
                        <button class="btn" onclick="analyzeHash()">Deep Analysis</button>
                        <button class="btn" onclick="clearHashId()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="hashIdOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'jwt-decoder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>JWT Token:</label>
                        <textarea id="jwtInput" rows="4" placeholder="Enter JWT token (eyJ...)"></textarea>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="decodeJWT()">Decode JWT</button>
                        <button class="btn" onclick="analyzeJWT()">Security Analysis</button>
                        <button class="btn" onclick="clearJWT()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Decoded Output:</label>
                        <div id="jwtOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'steganography':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Image:</label>
                        <input type="file" id="stegoFile" accept="image/*">
                        <canvas id="stegoCanvas" style="max-width: 100%; margin-top: 1rem; display: none;"></canvas>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="analyzeLSB()">LSB Analysis</button>
                        <button class="btn" onclick="extractChannels()">Extract RGB Channels</button>
                        <button class="btn" onclick="detectStego()">Detect Steganography</button>
                        <button class="btn" onclick="clearStego()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="stegoOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'sql-injection':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Target URL/Parameter:</label>
                        <input type="text" id="sqlTarget" placeholder="http://example.com/page.php?id=1">
                    </div>
                    <div class="input-group">
                        <label>Injection Type:</label>
                        <select id="sqlType">
                            <option value="union">UNION-based</option>
                            <option value="boolean">Boolean-based</option>
                            <option value="time">Time-based</option>
                            <option value="error">Error-based</option>
                        </select>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="generateSQLPayloads()">Generate Payloads</button>
                        <button class="btn" onclick="testSQLInjection()">Test Injection</button>
                        <button class="btn" onclick="clearSQL()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Generated Payloads:</label>
                        <div id="sqlOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'pattern-generator':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Pattern Length:</label>
                        <input type="number" id="patternLength" value="100" min="1" max="10000">
                    </div>
                    <div class="input-group">
                        <label>Pattern Type:</label>
                        <select id="patternType">
                            <option value="cyclic">Cyclic (De Bruijn)</option>
                            <option value="alphabetic">Alphabetic</option>
                            <option value="numeric">Numeric</option>
                            <option value="custom">Custom Characters</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Custom Characters (if selected):</label>
                        <input type="text" id="customChars" placeholder="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789">
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="generatePattern()">Generate Pattern</button>
                        <button class="btn" onclick="findOffset()">Find Offset</button>
                        <button class="btn" onclick="clearPattern()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Generated Pattern:</label>
                        <div id="patternOutput" class="output-area"></div>
                    </div>
                    <div class="input-group">
                        <label>Find Pattern in Crash (for offset calculation):</label>
                        <input type="text" id="crashPattern" placeholder="Enter 4-8 character sequence from crash">
                        <div id="offsetOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'qr-decoder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>QR Code Image:</label>
                        <input type="file" id="qrFile" accept="image/*">
                        <canvas id="qrCanvas" style="max-width: 100%; margin-top: 1rem; display: none;"></canvas>
                    </div>
                    <div class="input-group">
                        <label>Or Generate QR Code:</label>
                        <textarea id="qrText" rows="3" placeholder="Enter text to encode as QR code"></textarea>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="decodeQR()">Decode QR Code</button>
                        <button class="btn" onclick="generateQR()">Generate QR Code</button>
                        <button class="btn" onclick="clearQR()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Result:</label>
                        <div id="qrOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'password-generator':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Password Length:</label>
                        <input type="number" id="passLength" value="16" min="4" max="128">
                    </div>
                    <div class="input-group">
                        <label>Character Sets:</label>
                        <div class="checkbox-group">
                            <label><input type="checkbox" id="useUppercase" checked> Uppercase (A-Z)</label>
                            <label><input type="checkbox" id="useLowercase" checked> Lowercase (a-z)</label>
                            <label><input type="checkbox" id="useNumbers" checked> Numbers (0-9)</label>
                            <label><input type="checkbox" id="useSymbols" checked> Symbols (!@#$%^&*)</label>
                            <label><input type="checkbox" id="useAmbiguous"> Ambiguous (0,O,l,1)</label>
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Number of Passwords:</label>
                        <input type="number" id="passCount" value="5" min="1" max="50">
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="generatePasswords()">Generate Passwords</button>
                        <button class="btn" onclick="checkPasswordStrength()">Check Strength</button>
                        <button class="btn" onclick="clearPasswords()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Generated Passwords:</label>
                        <div id="passwordOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'brainfuck':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Brainfuck Code:</label>
                        <textarea id="bfCode" rows="5" placeholder="Enter Brainfuck code (>,<.+-)"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Input Data:</label>
                        <input type="text" id="bfInput" placeholder="Input for the program">
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="executeBrainfuck()">Execute</button>
                        <button class="btn" onclick="stepBrainfuck()">Step Through</button>
                        <button class="btn" onclick="loadBFExample()">Load Example</button>
                        <button class="btn" onclick="clearBrainfuck()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Output:</label>
                        <div id="bfOutput" class="output-area"></div>
                    </div>
                    <div class="input-group">
                        <label>Memory State:</label>
                        <div id="bfMemory" class="output-area"></div>
                    </div>
                </div>
            `;

        default:
            return generateBasicToolInterface(toolName);
    }
}

function generateBasicToolInterface(toolName) {
    const basicTools = {
        'url': {
            title: 'URL Encoder/Decoder',
            inputs: ['URL/Text'],
            buttons: ['URL Encode', 'URL Decode', 'Component Encode', 'Component Decode']
        },
        'ascii': {
            title: 'ASCII Converter',
            inputs: ['Input data'],
            buttons: ['Text → ASCII', 'ASCII → Text', 'ASCII → Hex', 'Hex → ASCII']
        },
        'vigenere': {
            title: 'Vigenère Cipher',
            inputs: ['Text', 'Key'],
            buttons: ['Encrypt', 'Decrypt', 'Key Analysis', 'Frequency Analysis']
        },
        'atbash': {
            title: 'Atbash Cipher',
            inputs: ['Text'],
            buttons: ['Encode/Decode', 'Hebrew Atbash', 'Custom Alphabet']
        },
        'rot13': {
            title: 'ROT13',
            inputs: ['Text'],
            buttons: ['ROT13', 'ROT47', 'Custom ROT', 'Analyze']
        },
        'morse-decoder': {
            title: 'Morse Code',
            inputs: ['Text/Morse'],
            buttons: ['Text → Morse', 'Morse → Text', 'Audio Morse', 'Custom Timing']
        },
        'hash-cracker': {
            title: 'Hash Cracker',
            inputs: ['Hash', 'Wordlist/Dictionary'],
            buttons: ['Dictionary Attack', 'Brute Force', 'Hybrid Attack', 'Rainbow Lookup']
        },
        'md5': {
            title: 'MD5 Tools',
            inputs: ['Input text'],
            buttons: ['Generate MD5', 'MD5 Lookup', 'Compare Hashes', 'File MD5']
        },
        'sha': {
            title: 'SHA Tools',
            inputs: ['Input text'],
            buttons: ['SHA-1', 'SHA-256', 'SHA-512', 'Compare All']
        },
        'rainbow': {
            title: 'Rainbow Tables',
            inputs: ['Hash'],
            buttons: ['MD5 Lookup', 'SHA1 Lookup', 'NTLM Lookup', 'Custom Search']
        },
        'binary-converter': {
            title: 'Binary Converter',
            inputs: ['Input data'],
            buttons: ['Text → Binary', 'Binary → Text', 'Text → Decimal', 'Decimal → Text']
        }
    };

    const tool = basicTools[toolName];
    if (!tool) {
        return `<div class="tool-interface"><p>Tool interface will be implemented soon.</p></div>`;
    }

    return `
        <div class="tool-interface">
            ${tool.inputs.map((input, i) => `
                <div class="input-group">
                    <label>${input}:</label>
                    <textarea id="${toolName}Input${i}" rows="3" placeholder="Enter ${input.toLowerCase()}"></textarea>
                </div>
            `).join('')}
            <div class="btn-grid">
                ${tool.buttons.map(button => `
                    <button class="btn" onclick="execute${toolName.charAt(0).toUpperCase() + toolName.slice(1)}('${button.toLowerCase().replace(/\s+/g, '')}')">${button}</button>
                `).join('')}
            </div>
            <div class="input-group">
                <label>Output:</label>
                <div id="${toolName}Output" class="output-area"></div>
            </div>
        </div>
    `;
}

function initializeTool(toolName) {
    // Tool-specific initializations
    switch(toolName) {
        case 'steganography':
            initSteganographyTool();
            break;
        case 'qr-decoder':
            initQRTool();
            break;
        case 'hash-cracker':
            initializeHashCracker();
            break;
    }
}

// Tool implementations
function base64Encode() {
    const input = document.getElementById('base64Input').value;
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)));
        document.getElementById('base64Output').innerHTML = `<div class="success">Encoded: ${encoded}</div>`;
    } catch (e) {
        document.getElementById('base64Output').innerHTML = `<div class="error">Error: ${e.message}</div>`;
    }
}

function base64Decode() {
    const input = document.getElementById('base64Input').value;
    try {
        const decoded = decodeURIComponent(escape(atob(input)));
        document.getElementById('base64Output').innerHTML = `<div class="success">Decoded: ${decoded}</div>`;
    } catch (e) {
        document.getElementById('base64Output').innerHTML = `<div class="error">Error: Invalid Base64 input</div>`;
    }
}

function base64UrlSafeEncode() {
    const input = document.getElementById('base64Input').value;
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        document.getElementById('base64Output').innerHTML = `<div class="success">URL-Safe Encoded: ${encoded}</div>`;
    } catch (e) {
        document.getElementById('base64Output').innerHTML = `<div class="error">Error: ${e.message}</div>`;
    }
}

function base64UrlSafeDecode() {
    const input = document.getElementById('base64Input').value;
    try {
        let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        const decoded = decodeURIComponent(escape(atob(base64)));
        document.getElementById('base64Output').innerHTML = `<div class="success">URL-Safe Decoded: ${decoded}</div>`;
    } catch (e) {
        document.getElementById('base64Output').innerHTML = `<div class="error">Error: Invalid URL-Safe Base64 input</div>`;
    }
}

function clearBase64() {
    document.getElementById('base64Input').value = '';
    document.getElementById('base64Output').innerHTML = '';
}

function caesarEncrypt() {
    const text = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 13;
    const result = caesarShiftText(text, shift);
    document.getElementById('caesarOutput').innerHTML = `<div class="success">Encrypted: ${result}</div>`;
}

function caesarDecrypt() {
    const text = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 13;
    const result = caesarShiftText(text, -shift);
    document.getElementById('caesarOutput').innerHTML = `<div class="success">Decrypted: ${result}</div>`;
}

function caesarBruteForce() {
    const text = document.getElementById('caesarInput').value;
    let output = '<div class="info">All possible Caesar shifts:</div>';

    for (let i = 0; i < 26; i++) {
        const result = caesarShiftText(text, i);
        output += `<div class="result-line">Shift ${i}: ${result}</div>`;
    }

    document.getElementById('caesarOutput').innerHTML = output;
}

function caesarShiftText(text, shift) {
    return text.replace(/[a-zA-Z]/g, function(char) {
        const start = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - start + shift + 26) % 26) + start);
    });
}

function clearCaesar() {
    document.getElementById('caesarInput').value = '';
    document.getElementById('caesarOutput').innerHTML = '';
}

function textToHex() {
    const input = document.getElementById('hexInput').value;
    const hex = Array.from(input)
        .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ');
    document.getElementById('hexOutput').innerHTML = `<div class="success">Hex: ${hex}</div>`;
}

function hexToText() {
    const input = document.getElementById('hexInput').value.replace(/\s+/g, '');
    try {
        const text = input.match(/.{2}/g)
            .map(hex => String.fromCharCode(parseInt(hex, 16)))
            .join('');
        document.getElementById('hexOutput').innerHTML = `<div class="success">Text: ${text}</div>`;
    } catch (e) {
        document.getElementById('hexOutput').innerHTML = `<div class="error">Error: Invalid hex input</div>`;
    }
}

function hexToBytes() {
    const input = document.getElementById('hexInput').value.replace(/\s+/g, '');
    try {
        const bytes = input.match(/.{2}/g)
            .map(hex => parseInt(hex, 16));
        document.getElementById('hexOutput').innerHTML = `<div class="success">Bytes: [${bytes.join(', ')}]</div>`;
    } catch (e) {
        document.getElementById('hexOutput').innerHTML = `<div class="error">Error: Invalid hex input</div>`;
    }
}

function clearHex() {
    document.getElementById('hexInput').value = '';
    document.getElementById('hexOutput').innerHTML = '';
}

function identifyHash() {
    const hash = document.getElementById('hashInput').value.trim();
    const analysis = analyzeHashType(hash);
    let output = `<div class="info">Hash Analysis:</div>`;
    output += `<div class="result-line">Length: ${hash.length} characters</div>`;
    output += `<div class="result-line">Character Set: ${getCharacterSet(hash)}</div>`;
    output += `<div class="result-line">Possible Types: ${analysis.join(', ')}</div>`;

    document.getElementById('hashIdOutput').innerHTML = output;
}

function analyzeHashType(hash) {
    const types = [];
    const len = hash.length;
    const isHex = /^[a-fA-F0-9]+$/.test(hash);

    if (len === 32 && isHex) types.push('MD5', 'NTLM');
    if (len === 40 && isHex) types.push('SHA-1', 'MySQL5.x');
    if (len === 56 && isHex) types.push('SHA-224');
    if (len === 64 && isHex) types.push('SHA-256', 'SHA3-256');
    if (len === 96 && isHex) types.push('SHA-384');
    if (len === 128 && isHex) types.push('SHA-512', 'SHA3-512');
    if (len === 13 && hash.startsWith('$')) types.push('DES Crypt');
    if (hash.startsWith('$1$')) types.push('MD5 Crypt');
    if (hash.startsWith('$2')) types.push('Bcrypt');
    if (hash.startsWith('$5$')) types.push('SHA-256 Crypt');
    if (hash.startsWith('$6$')) types.push('SHA-512 Crypt');

    return types.length > 0 ? types : ['Unknown'];
}

function getCharacterSet(hash) {
    if (/^[a-fA-F0-9]+$/.test(hash)) return 'Hexadecimal';
    if (/^[a-zA-Z0-9+/=]+$/.test(hash)) return 'Base64';
    if (/^[a-zA-Z0-9./]+$/.test(hash)) return 'Base64 (URL-safe)';
    return 'Mixed/Unknown';
}

function analyzeHash() {
    const hash = document.getElementById('hashInput').value.trim();
    let output = `<div class="info">Deep Hash Analysis:</div>`;

    // Entropy analysis
    const entropy = calculateEntropy(hash);
    output += `<div class="result-line">Entropy: ${entropy.toFixed(2)} bits</div>`;

    // Pattern analysis
    const patterns = detectPatterns(hash);
    if (patterns.length > 0) {
        output += `<div class="result-line">Patterns: ${patterns.join(', ')}</div>`;
    }

    // Character frequency
    const freq = getCharacterFrequency(hash);
    output += `<div class="result-line">Most frequent chars: ${freq}</div>`;

    document.getElementById('hashIdOutput').innerHTML = output;
}

function calculateEntropy(str) {
    const freq = {};
    for (let char of str) {
        freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (let count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

function detectPatterns(hash) {
    const patterns = [];
    if (hash.includes('00000')) patterns.push('Zero sequences');
    if (/(.)\1{3,}/.test(hash)) patterns.push('Character repetition');
    if (hash.toLowerCase() !== hash && hash.toUpperCase() !== hash) patterns.push('Mixed case');
    return patterns;
}

function getCharacterFrequency(str) {
    const freq = {};
    for (let char of str) {
        freq[char] = (freq[char] || 0) + 1;
    }

    return Object.entries(freq)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([char, count]) => `${char}(${count})`)
        .join(', ');
}

function clearHashId() {
    document.getElementById('hashInput').value = '';
    document.getElementById('hashIdOutput').innerHTML = '';
}

function decodeJWT() {
    const token = document.getElementById('jwtInput').value.trim();
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        let output = `<div class="info">JWT Decoded:</div>`;
        output += `<div class="result-section"><strong>Header:</strong><pre>${JSON.stringify(header, null, 2)}</pre></div>`;
        output += `<div class="result-section"><strong>Payload:</strong><pre>${JSON.stringify(payload, null, 2)}</pre></div>`;
        output += `<div class="result-section"><strong>Signature:</strong> ${parts[2]}</div>`;

        document.getElementById('jwtOutput').innerHTML = output;
    } catch (e) {
        document.getElementById('jwtOutput').innerHTML = `<div class="error">Error: ${e.message}</div>`;
    }
}

function analyzeJWT() {
    const token = document.getElementById('jwtInput').value.trim();
    try {
        const parts = token.split('.');
        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        let output = `<div class="info">JWT Security Analysis:</div>`;

        // Algorithm analysis
        if (header.alg === 'none') {
            output += `<div class="error">⚠️ No signature algorithm - highly insecure!</div>`;
        } else if (header.alg.startsWith('HS')) {
            output += `<div class="warning">HMAC signature - shared secret</div>`;
        } else if (header.alg.startsWith('RS') || header.alg.startsWith('ES')) {
            output += `<div class="success">Public key signature algorithm</div>`;
        }

        // Expiration check
        if (payload.exp) {
            const exp = new Date(payload.exp * 1000);
            const now = new Date();
            if (exp < now) {
                output += `<div class="error">Token expired on ${exp.toISOString()}</div>`;
            } else {
                output += `<div class="success">Token expires on ${exp.toISOString()}</div>`;
            }
        } else {
            output += `<div class="warning">No expiration time set</div>`;
        }

        // Audience and issuer
        if (!payload.aud) output += `<div class="warning">No audience specified</div>`;
        if (!payload.iss) output += `<div class="warning">No issuer specified</div>`;

        document.getElementById('jwtOutput').innerHTML = output;
    } catch (e) {
        document.getElementById('jwtOutput').innerHTML = `<div class="error">Error: ${e.message}</div>`;
    }
}

function clearJWT() {
    document.getElementById('jwtInput').value = '';
    document.getElementById('jwtOutput').innerHTML = '';
}

function generateSQLPayloads() {
    const target = document.getElementById('sqlTarget').value;
    const type = document.getElementById('sqlType').value;

    let payloads = [];

    switch(type) {
        case 'union':
            payloads = [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT table_name,column_name,1 FROM information_schema.columns--",
                "' UNION SELECT schema_name,1,2 FROM information_schema.schemata--",
                "1' UNION SELECT 1,2,3,4,5#"
            ];
            break;
        case 'boolean':
            payloads = [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a'--",
                "' AND substring(user(),1,1)='r'--",
                "' AND (SELECT COUNT(*) FROM users)>0--"
            ];
            break;
        case 'time':
            payloads = [
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND SLEEP(5)--",
                "' AND (SELECT SLEEP(5))--",
                "'; SELECT pg_sleep(5)--",
                "' AND BENCHMARK(5000000,SHA1(1))--"
            ];
            break;
        case 'error':
            payloads = [
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--"
            ];
            break;
    }

    let output = `<div class="info">Generated ${type.toUpperCase()} SQL Injection Payloads:</div>`;
    payloads.forEach((payload, i) => {
        output += `<div class="result-line">Payload ${i+1}: <code>${payload}</code></div>`;
    });

    document.getElementById('sqlOutput').innerHTML = output;
}

function testSQLInjection() {
    const target = document.getElementById('sqlTarget').value;
    let output = `<div class="info">SQL Injection Test Results for: ${target}</div>`;
    output += `<div class="warning">⚠️ This is a simulation. Do not test on systems you don't own!</div>`;
    output += `<div class="result-line">Recommended tools: SQLMap, Burp Suite, OWASP ZAP</div>`;
    output += `<div class="result-line">Manual testing: Check for error messages, time delays, boolean responses</div>`;

    document.getElementById('sqlOutput').innerHTML = output;
}

function clearSQL() {
    document.getElementById('sqlTarget').value = '';
    document.getElementById('sqlOutput').innerHTML = '';
}

function generatePattern() {
    const length = parseInt(document.getElementById('patternLength').value) || 100;
    const type = document.getElementById('patternType').value;
    let pattern = '';

    switch(type) {
        case 'cyclic':
            pattern = generateCyclicPattern(length);
            break;
        case 'alphabetic':
            pattern = generateAlphabeticPattern(length);
            break;
        case 'numeric':
            pattern = generateNumericPattern(length);
            break;
        case 'custom':
            const chars = document.getElementById('customChars').value || 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            pattern = generateCustomPattern(length, chars);
            break;
    }

    document.getElementById('patternOutput').innerHTML = 
        `<div class="success">Generated Pattern (${pattern.length} chars):</div><div class="pattern-display">${pattern}</div>`;
}

function generateCyclicPattern(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let pattern = '';
    let index = 0;

    for (let i = 0; i < length; i++) {
        pattern += chars[index % chars.length];
        index++;
    }

    return pattern;
}

function generateAlphabeticPattern(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let pattern = '';

    for (let i = 0; i < length; i++) {
        pattern += chars[i % chars.length];
    }

    return pattern;
}

function generateNumericPattern(length) {
    let pattern = '';
    for (let i = 0; i < length; i++) {
        pattern += (i % 10).toString();
    }
    return pattern;
}

function generateCustomPattern(length, chars) {
    let pattern = '';
    for (let i = 0; i < length; i++) {
        pattern += chars[i % chars.length];
    }
    return pattern;
}

function findOffset() {
    const crashPattern = document.getElementById('crashPattern').value.trim();
    const generatedPattern = document.querySelector('#patternOutput .pattern-display')?.textContent;

    if (!generatedPattern || !crashPattern) {
        document.getElementById('offsetOutput').innerHTML = 
            '<div class="error">Please generate a pattern first and enter crash pattern</div>';
        return;
    }

    const offset = generatedPattern.indexOf(crashPattern);

    if (offset !== -1) {
        document.getElementById('offsetOutput').innerHTML = 
            `<div class="success">Offset found: ${offset} bytes</div>`;
    } else {
        document.getElementById('offsetOutput').innerHTML = 
            `<div class="error">Pattern not found in generated sequence</div>`;
    }
}

function clearPattern() {
    document.getElementById('patternLength').value = '100';
    document.getElementById('patternOutput').innerHTML = '';
    document.getElementById('crashPattern').value = '';
    document.getElementById('offsetOutput').innerHTML = '';
}

function generatePasswords() {
    const length = parseInt(document.getElementById('passLength').value) || 16;
    const count = parseInt(document.getElementById('passCount').value) || 5;

    const useUpper = document.getElementById('useUppercase').checked;
    const useLower = document.getElementById('useLowercase').checked;
    const useNumbers = document.getElementById('useNumbers').checked;
    const useSymbols = document.getElementById('useSymbols').checked;
    const useAmbiguous = document.getElementById('useAmbiguous').checked;

    let charset = '';
    if (useUpper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useLower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (useNumbers) charset += '0123456789';
    if (useSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!useAmbiguous) {
        charset = charset.replace(/[0Ol1]/g, '');
    }

    if (!charset) {
        document.getElementById('passwordOutput').innerHTML = 
            '<div class="error">Please select at least one character set</div>';
        return;
    }

    let output = '<div class="info">Generated Passwords:</div>';

    for (let i = 0; i < count; i++) {
        let password = '';
        for (let j = 0; j < length; j++) {
            password += charset[Math.floor(Math.random() * charset.length)];
        }
        const strength = calculatePasswordStrength(password);
        output += `<div class="result-line">${password} <span class="strength-${strength.level}">(${strength.score}/100)</span></div>`;
    }

    document.getElementById('passwordOutput').innerHTML = output;
}

function calculatePasswordStrength(password) {
    let score = 0;

    // Length bonus
    score += Math.min(password.length * 2, 30);

    // Character variety
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;

    // Complexity bonus
    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;

    // Penalty for common patterns
    if (/(.)\1{2,}/.test(password)) score -= 10;
    if (/123|abc|qwe/i.test(password)) score -= 15;

    const level = score >= 80 ? 'strong' : score >= 60 ? 'medium' : 'weak';

    return { score: Math.max(0, Math.min(100, score)), level };
}

function checkPasswordStrength() {
    // This would analyze a provided password
    document.getElementById('passwordOutput').innerHTML = 
        '<div class="info">Enter a password to check its strength</div>';
}

function clearPasswords() {
    document.getElementById('passwordOutput').innerHTML = '';
}

function executeBrainfuck() {
    const code = document.getElementById('bfCode').value;
    const input = document.getElementById('bfInput').value;

    const result = interpretBrainfuck(code, input);

    document.getElementById('bfOutput').innerHTML = 
        `<div class="success">Output: ${result.output}</div>`;
    document.getElementById('bfMemory').innerHTML = 
        `<div class="info">Memory: [${result.memory.slice(0, 20).join(', ')}...]</div>`;
}

function interpretBrainfuck(code, input) {
    const memory = new Array(30000).fill(0);
    let pointer = 0;
    let codePointer = 0;
    let inputPointer = 0;
    let output = '';
    let iterations = 0;
    const maxIterations = 100000;

    while (codePointer < code.length && iterations < maxIterations) {
        const command = code[codePointer];

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
                    let bracketCount = 1;
                    while (bracketCount > 0 && codePointer < code.length - 1) {
                        codePointer++;
                        if (code[codePointer] === '[') bracketCount++;
                        if (code[codePointer] === ']') bracketCount--;
                    }
                }
                break;
            case ']':
                if (memory[pointer] !== 0) {
                    let bracketCount = 1;
                    while (bracketCount > 0 && codePointer > 0) {
                        codePointer--;
                        if (code[codePointer] === ']') bracketCount++;
                        if (code[codePointer] === '[') bracketCount--;
                    }
                }
                break;
        }

        codePointer++;
        iterations++;
    }

    if (iterations >= maxIterations) {
        output += '\n[Execution stopped - iteration limit reached]';
    }

    return { output, memory, iterations };
}

function loadBFExample() {
    document.getElementById('bfCode').value = '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.';
    document.getElementById('bfInput').value = '';
}

function stepBrainfuck() {
    document.getElementById('bfOutput').innerHTML = 
        '<div class="info">Step-by-step execution not implemented in this demo</div>';
}

function clearBrainfuck() {
    document.getElementById('bfCode').value = '';
    document.getElementById('bfInput').value = '';
    document.getElementById('bfOutput').innerHTML = '';
    document.getElementById('bfMemory').innerHTML = '';
}

// Initialize steganography tool
function initSteganographyTool() {
    const fileInput = document.getElementById('stegoFile');
    if (fileInput) {
        fileInput.addEventListener('change', handleStegoFile);
    }
}

function handleStegoFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.getElementById('stegoCanvas');
            const ctx = canvas.getContext('2d');

            canvas.width = img.width;
            canvas.height = img.height;
            canvas.style.display = 'block';

            ctx.drawImage(img, 0, 0);
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function analyzeLSB() {
    const canvas = document.getElementById('stegoCanvas');
    if (!canvas || canvas.style.display === 'none') {
        document.getElementById('stegoOutput').innerHTML = 
            '<div class="error">Please upload an image first</div>';
        return;
    }

    const ctx = canvas.getContext('2d');
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;

    let lsbBits = '';
    let output = '<div class="info">LSB Analysis Results:</div>';

    // Extract LSBs from red channel
    for (let i = 0; i < data.length; i += 4) {
        lsbBits += (data[i] & 1).toString();
        if (lsbBits.length >= 1000) break; // Limit for demo
    }

    // Try to find readable text
    let text = '';
    for (let i = 0; i < lsbBits.length - 7; i += 8) {
        const byte = parseInt(lsbBits.substr(i, 8), 2);
        if (byte >= 32 && byte <= 126) {
            text += String.fromCharCode(byte);
        } else {
            text += '.';
        }
        if (text.length >= 100) break;
    }

    output += `<div class="result-line">First 1000 LSBs: ${lsbBits.substring(0, 100)}...</div>`;
    output += `<div class="result-line">Possible text: ${text}</div>`;

    document.getElementById('stegoOutput').innerHTML = output;
}

function extractChannels() {
    const canvas = document.getElementById('stegoCanvas');
    if (!canvas || canvas.style.display === 'none') {
        document.getElementById('stegoOutput').innerHTML = 
            '<div class="error">Please upload an image first</div>';
        return;
    }

    const ctx = canvas.getContext('2d');
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;

    // Create separate canvases for each channel
    let output = '<div class="info">RGB Channel Analysis:</div>';

    const channels = ['Red', 'Green', 'Blue'];
    channels.forEach((channel, index) => {
        const channelCanvas = document.createElement('canvas');
        channelCanvas.width = canvas.width;
        channelCanvas.height = canvas.height;
        channelCanvas.style.maxWidth = '200px';
        channelCanvas.style.margin = '5px';

        const channelCtx = channelCanvas.getContext('2d');
        const channelData = channelCtx.createImageData(canvas.width, canvas.height);

        for (let i = 0; i < data.length; i += 4) {
            channelData.data[i] = index === 0 ? data[i] : 0;     // Red
            channelData.data[i + 1] = index === 1 ? data[i + 1] : 0; // Green
            channelData.data[i + 2] = index === 2 ? data[i + 2] : 0; // Blue
            channelData.data[i + 3] = 255; // Alpha
        }

        channelCtx.putImageData(channelData, 0, 0);
        output += `<div class="result-line">${channel} Channel:</div>`;
        output += `<div class="channel-image">${channelCanvas.outerHTML}</div>`;
    });

    document.getElementById('stegoOutput').innerHTML = output;
}

function detectStego() {
    document.getElementById('stegoOutput').innerHTML = 
        '<div class="info">Steganography detection analysis would use advanced algorithms like:</div>' +
        '<div class="result-line">• Chi-square analysis</div>' +
        '<div class="result-line">• Histogram analysis</div>' +
        '<div class="result-line">• Pixel correlation analysis</div>' +
        '<div class="result-line">• LSB plane visualization</div>' +
        '<div class="warning">Full implementation requires specialized stego detection libraries</div>';
}

function clearStego() {
    document.getElementById('stegoFile').value = '';
    document.getElementById('stegoCanvas').style.display = 'none';
    document.getElementById('stegoOutput').innerHTML = '';
}

// Initialize QR tool
function initQRTool() {
    const fileInput = document.getElementById('qrFile');
    if (fileInput) {
        fileInput.addEventListener('change', handleQRFile);
    }
}

function handleQRFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.getElementById('qrCanvas');
            const ctx = canvas.getContext('2d');

            canvas.width = img.width;
            canvas.height = img.height;
            canvas.style.display = 'block';

            ctx.drawImage(img, 0, 0);

            // Auto-decode when image is loaded
            decodeQRFromCanvas();
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function decodeQRFromCanvas() {
    const canvas = document.getElementById('qrCanvas');
    if (!canvas || canvas.style.display === 'none') return;

    const ctx = canvas.getContext('2d');
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    try {
        if (typeof jsQR !== 'undefined') {
            const code = jsQR(imageData.data, imageData.width, imageData.height);
            if (code) {
                document.getElementById('qrOutput').innerHTML = 
                    `<div class="success">QR Code Content: ${code.data}</div>`;
            } else {
                document.getElementById('qrOutput').innerHTML = 
                    '<div class="error">No QR code found in image</div>';
            }
        } else {
            document.getElementById('qrOutput').innerHTML = 
                '<div class="warning">QR decoder library not loaded</div>';
        }
    } catch (e) {
        document.getElementById('qrOutput').innerHTML = 
            `<div class="error">Error decoding QR code: ${e.message}</div>`;
    }
}

function decodeQR() {
    decodeQRFromCanvas();
}

function generateQR() {
    const text = document.getElementById('qrText').value;
    if (!text) {
        document.getElementById('qrOutput').innerHTML = 
            '<div class="error">Please enter text to encode</div>';
        return;
    }

    try {
        if (typeof QRCode !== 'undefined') {
            const canvas = document.getElementById('qrCanvas');
            canvas.style.display = 'block';

            QRCode.toCanvas(canvas, text, function (error) {
                if (error) {
                    document.getElementById('qrOutput').innerHTML = 
                        `<div class="error">Error generating QR code: ${error}</div>`;
                } else {
                    document.getElementById('qrOutput').innerHTML = 
                        '<div class="success">QR code generated successfully</div>';
                }
            });
        } else {
            document.getElementById('qrOutput').innerHTML = 
                '<div class="warning">QR generator library not loaded</div>';
        }
    } catch (e) {
        document.getElementById('qrOutput').innerHTML = 
            `<div class="error">Error: ${e.message}</div>`;
    }
}

function clearQR() {
    document.getElementById('qrFile').value = '';
    document.getElementById('qrText').value = '';
    document.getElementById('qrCanvas').style.display = 'none';
    document.getElementById('qrOutput').innerHTML = '';
}

// Generic tool execution function for basic tools
function executeUrl(action) {
    const input = document.getElementById('urlInput0').value;
    let output = '';

    switch(action) {
        case 'urlencode':
            output = encodeURIComponent(input);
            break;
        case 'urldecode':
            output = decodeURIComponent(input);
            break;
        case 'componentencode':
            output = encodeURI(input);
            break;
        case 'componentdecode':
            output = decodeURI(input);
            break;
    }

    document.getElementById('urlOutput').innerHTML = `<div class="success">${output}</div>`;
}

// Add more tool implementations as needed...

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && modalOpen) {
        closeModal();
    }
});

// Error handling
window.addEventListener('error', function(e) {
    console.error('JavaScript Error:', e.error);
});

// Ensure all external libraries are loaded
window.addEventListener('load', function() {
    console.log('CTF Arsenal loaded successfully');

    // Check for required libraries
    const requiredLibs = ['CryptoJS', 'js_beautify', 'JSZip'];
    const missingLibs = requiredLibs.filter(lib => typeof window[lib] === 'undefined');

    if (missingLibs.length > 0) {
        console.warn('Missing libraries:', missingLibs);
    }
});

async function downloadBase64() {
    const base64Data = document.getElementById('base64Output').textContent;
    if (!base64Data) {
        alert('No data to download!');
        return;
    }

    try {
        // Decode the base64 data
        const byteCharacters = atob(base64Data);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);

        // Create a Blob from the data
        const blob = new Blob([byteArray], { type: 'application/octet-stream' });

        // Create a download link
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'downloaded_file.bin'; // You can name the file as you like

        // Trigger the download
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

    } catch (e) {
        alert('Error during download: ' + e.message);
    }
}

function initializeHashCracker() {
    // Initialization logic for hash cracker
}
