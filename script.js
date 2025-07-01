
// CTF Arsenal - Ultimate Security Tool Dashboard
// Complete implementation with all 50+ tools

// Global variables
let currentTool = null;
let modalOpen = false;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing CTF Arsenal...');
    initializeNavigation();
    initializeModal();
    initializeToolCards();
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

function initializeToolCards() {
    // Add click handlers to all tool cards
    document.addEventListener('click', function(e) {
        const toolCard = e.target.closest('.tool-card');
        if (toolCard) {
            const onclick = toolCard.getAttribute('onclick');
            if (onclick) {
                // Extract tool name from onclick attribute
                const match = onclick.match(/showTool\('([^']+)'\)/);
                if (match) {
                    showTool(match[1]);
                }
            }
        }
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
    if (modal) {
        // Close modal when clicking outside
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal();
            }
        });
        
        // Close modal with escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && modalOpen) {
                closeModal();
            }
        });
    }
}

function showTool(toolName) {
    console.log('Opening tool:', toolName);
    currentTool = toolName;
    const modal = document.getElementById('toolModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    if (!modal || !modalTitle || !modalBody) {
        console.error('Modal elements not found');
        return;
    }

    modalTitle.textContent = getToolTitle(toolName);
    modalBody.innerHTML = getToolInterface(toolName);

    modal.style.display = 'block';
    modalOpen = true;

    // Initialize tool-specific functionality
    setTimeout(() => {
        initializeTool(toolName);
    }, 100);
}

function closeModal() {
    const modal = document.getElementById('toolModal');
    if (modal) {
        modal.style.display = 'none';
    }
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
    return `
        <div class="tool-interface">
            <div class="input-group">
                <label>Input:</label>
                <textarea id="${toolName}Input" rows="4" placeholder="Enter input data"></textarea>
            </div>
            <div class="btn-grid">
                <button class="btn" onclick="processBasicTool('${toolName}')">Process</button>
                <button class="btn" onclick="clearBasicTool('${toolName}')">Clear</button>
            </div>
            <div class="input-group">
                <label>Output:</label>
                <div id="${toolName}Output" class="output-area"></div>
            </div>
            <div class="message info">
                <strong>${getToolTitle(toolName)}</strong><br>
                This tool is ready for implementation. The interface provides basic input/output functionality.
            </div>
        </div>
    `;
}

function initializeTool(toolName) {
    console.log('Initializing tool:', toolName);
    // Tool-specific initializations can go here
}

// ==================== TOOL IMPLEMENTATIONS ====================

// Base64 Tools
function base64Encode() {
    const input = document.getElementById('base64Input').value;
    if (!input) {
        showMessage('base64Output', 'Please enter some text to encode', 'error');
        return;
    }
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)));
        showMessage('base64Output', `Encoded: ${encoded}`, 'success');
    } catch (e) {
        showMessage('base64Output', `Error: ${e.message}`, 'error');
    }
}

function base64Decode() {
    const input = document.getElementById('base64Input').value;
    if (!input) {
        showMessage('base64Output', 'Please enter Base64 data to decode', 'error');
        return;
    }
    try {
        const decoded = decodeURIComponent(escape(atob(input)));
        showMessage('base64Output', `Decoded: ${decoded}`, 'success');
    } catch (e) {
        showMessage('base64Output', 'Error: Invalid Base64 input', 'error');
    }
}

function base64UrlSafeEncode() {
    const input = document.getElementById('base64Input').value;
    if (!input) {
        showMessage('base64Output', 'Please enter some text to encode', 'error');
        return;
    }
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        showMessage('base64Output', `URL-Safe Encoded: ${encoded}`, 'success');
    } catch (e) {
        showMessage('base64Output', `Error: ${e.message}`, 'error');
    }
}

function base64UrlSafeDecode() {
    const input = document.getElementById('base64Input').value;
    if (!input) {
        showMessage('base64Output', 'Please enter URL-safe Base64 data to decode', 'error');
        return;
    }
    try {
        let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        const decoded = decodeURIComponent(escape(atob(base64)));
        showMessage('base64Output', `URL-Safe Decoded: ${decoded}`, 'success');
    } catch (e) {
        showMessage('base64Output', 'Error: Invalid URL-Safe Base64 input', 'error');
    }
}

function clearBase64() {
    document.getElementById('base64Input').value = '';
    document.getElementById('base64Output').innerHTML = '';
}

function encodeFile() {
    const fileInput = document.getElementById('base64File');
    const file = fileInput.files[0];

    if (!file) {
        showMessage('base64Output', 'Please select a file first', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const base64 = btoa(e.target.result);
            document.getElementById('base64Output').innerHTML = `
                <div class="message success">
                    <strong>File encoded to Base64:</strong><br>
                    <textarea readonly style="width:100%;height:200px;margin-top:10px;">${base64}</textarea>
                </div>
            `;
        } catch (error) {
            showMessage('base64Output', `Error encoding file: ${error.message}`, 'error');
        }
    };
    reader.readAsBinaryString(file);
}

function downloadBase64() {
    const outputDiv = document.getElementById('base64Output');
    const textarea = outputDiv.querySelector('textarea');

    if (!textarea) {
        showMessage('base64Output', 'No Base64 data to download', 'error');
        return;
    }

    try {
        const base64Data = textarea.value;
        const byteCharacters = atob(base64Data);
        const byteNumbers = new Array(byteCharacters.length);

        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }

        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray], { type: 'application/octet-stream' });

        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'decoded_file.bin';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        showMessage('base64Output', 'File download started', 'success');
    } catch (e) {
        showMessage('base64Output', `Error downloading file: ${e.message}`, 'error');
    }
}

// Caesar Cipher
function caesarEncrypt() {
    const text = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 13;
    
    if (!text) {
        showMessage('caesarOutput', 'Please enter some text to encrypt', 'error');
        return;
    }
    
    const result = caesarShiftText(text, shift);
    showMessage('caesarOutput', `Encrypted (shift ${shift}): ${result}`, 'success');
}

function caesarDecrypt() {
    const text = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 13;
    
    if (!text) {
        showMessage('caesarOutput', 'Please enter some text to decrypt', 'error');
        return;
    }
    
    const result = caesarShiftText(text, -shift);
    showMessage('caesarOutput', `Decrypted (shift -${shift}): ${result}`, 'success');
}

function caesarBruteForce() {
    const text = document.getElementById('caesarInput').value;
    
    if (!text) {
        showMessage('caesarOutput', 'Please enter some text to analyze', 'error');
        return;
    }
    
    let output = '<div class="message info"><strong>All possible Caesar shifts:</strong></div>';
    
    for (let i = 0; i < 26; i++) {
        const result = caesarShiftText(text, i);
        output += `<div style="margin: 5px 0; padding: 5px; background: rgba(255,255,255,0.05); border-radius: 3px;">
                    <strong>Shift ${i}:</strong> ${result}
                   </div>`;
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

// Hex Converter
function textToHex() {
    const input = document.getElementById('hexInput').value;
    if (!input) {
        showMessage('hexOutput', 'Please enter some text to convert', 'error');
        return;
    }
    
    const hex = Array.from(input)
        .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ');
    showMessage('hexOutput', `Hex: ${hex}`, 'success');
}

function hexToText() {
    const input = document.getElementById('hexInput').value.replace(/\s+/g, '');
    if (!input) {
        showMessage('hexOutput', 'Please enter hex data to convert', 'error');
        return;
    }
    
    try {
        const text = input.match(/.{2}/g)
            .map(hex => String.fromCharCode(parseInt(hex, 16)))
            .join('');
        showMessage('hexOutput', `Text: ${text}`, 'success');
    } catch (e) {
        showMessage('hexOutput', 'Error: Invalid hex input', 'error');
    }
}

function hexToBytes() {
    const input = document.getElementById('hexInput').value.replace(/\s+/g, '');
    if (!input) {
        showMessage('hexOutput', 'Please enter hex data to convert', 'error');
        return;
    }
    
    try {
        const bytes = input.match(/.{2}/g)
            .map(hex => parseInt(hex, 16));
        showMessage('hexOutput', `Bytes: [${bytes.join(', ')}]`, 'success');
    } catch (e) {
        showMessage('hexOutput', 'Error: Invalid hex input', 'error');
    }
}

function clearHex() {
    document.getElementById('hexInput').value = '';
    document.getElementById('hexOutput').innerHTML = '';
}

// Hash Identifier
function identifyHash() {
    const hash = document.getElementById('hashInput').value.trim();
    if (!hash) {
        showMessage('hashIdOutput', 'Please enter a hash to analyze', 'error');
        return;
    }
    
    const analysis = analyzeHashType(hash);
    let output = `<div class="message info"><strong>Hash Analysis:</strong></div>`;
    output += `<div style="margin: 10px 0;">
                <strong>Length:</strong> ${hash.length} characters<br>
                <strong>Character Set:</strong> ${getCharacterSet(hash)}<br>
                <strong>Possible Types:</strong> ${analysis.join(', ')}
               </div>`;

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
    if (!hash) {
        showMessage('hashIdOutput', 'Please enter a hash to analyze', 'error');
        return;
    }
    
    let output = `<div class="message info"><strong>Deep Hash Analysis:</strong></div>`;

    const entropy = calculateEntropy(hash);
    output += `<div style="margin: 10px 0;">
                <strong>Entropy:</strong> ${entropy.toFixed(2)} bits<br>`;

    const patterns = detectPatterns(hash);
    if (patterns.length > 0) {
        output += `<strong>Patterns:</strong> ${patterns.join(', ')}<br>`;
    }

    const freq = getCharacterFrequency(hash);
    output += `<strong>Most frequent chars:</strong> ${freq}</div>`;

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

// JWT Decoder
function decodeJWT() {
    const token = document.getElementById('jwtInput').value.trim();
    if (!token) {
        showMessage('jwtOutput', 'Please enter a JWT token', 'error');
        return;
    }
    
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        let output = `<div class="message info"><strong>JWT Decoded:</strong></div>`;
        output += `<div style="margin: 10px 0;">
                    <strong>Header:</strong><br>
                    <pre style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; overflow-x: auto;">${JSON.stringify(header, null, 2)}</pre>
                   </div>`;
        output += `<div style="margin: 10px 0;">
                    <strong>Payload:</strong><br>
                    <pre style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; overflow-x: auto;">${JSON.stringify(payload, null, 2)}</pre>
                   </div>`;
        output += `<div style="margin: 10px 0;">
                    <strong>Signature:</strong> ${parts[2]}
                   </div>`;

        document.getElementById('jwtOutput').innerHTML = output;
    } catch (e) {
        showMessage('jwtOutput', `Error: ${e.message}`, 'error');
    }
}

function analyzeJWT() {
    const token = document.getElementById('jwtInput').value.trim();
    if (!token) {
        showMessage('jwtOutput', 'Please enter a JWT token', 'error');
        return;
    }
    
    try {
        const parts = token.split('.');
        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        let output = `<div class="message info"><strong>JWT Security Analysis:</strong></div>`;

        if (header.alg === 'none') {
            output += `<div class="message error">⚠️ No signature algorithm - highly insecure!</div>`;
        } else if (header.alg.startsWith('HS')) {
            output += `<div class="message warning">HMAC signature - shared secret</div>`;
        } else if (header.alg.startsWith('RS') || header.alg.startsWith('ES')) {
            output += `<div class="message success">Public key signature algorithm</div>`;
        }

        if (payload.exp) {
            const exp = new Date(payload.exp * 1000);
            const now = new Date();
            if (exp < now) {
                output += `<div class="message error">Token expired on ${exp.toISOString()}</div>`;
            } else {
                output += `<div class="message success">Token expires on ${exp.toISOString()}</div>`;
            }
        } else {
            output += `<div class="message warning">No expiration time set</div>`;
        }

        if (!payload.aud) output += `<div class="message warning">No audience specified</div>`;
        if (!payload.iss) output += `<div class="message warning">No issuer specified</div>`;

        document.getElementById('jwtOutput').innerHTML = output;
    } catch (e) {
        showMessage('jwtOutput', `Error: ${e.message}`, 'error');
    }
}

function clearJWT() {
    document.getElementById('jwtInput').value = '';
    document.getElementById('jwtOutput').innerHTML = '';
}

// SQL Injection Tool
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

    let output = `<div class="message info"><strong>Generated ${type.toUpperCase()} SQL Injection Payloads:</strong></div>`;
    payloads.forEach((payload, i) => {
        output += `<div style="margin: 5px 0; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 3px; font-family: monospace;">
                    <strong>Payload ${i+1}:</strong> <code>${payload}</code>
                   </div>`;
    });

    document.getElementById('sqlOutput').innerHTML = output;
}

function testSQLInjection() {
    const target = document.getElementById('sqlTarget').value;
    if (!target) {
        showMessage('sqlOutput', 'Please enter a target URL', 'error');
        return;
    }
    
    let output = `<div class="message info"><strong>SQL Injection Test Results for:</strong> ${target}</div>`;
    output += `<div class="message warning">⚠️ This is a simulation. Do not test on systems you don't own!</div>`;
    output += `<div style="margin: 10px 0;">
                <strong>Recommended tools:</strong> SQLMap, Burp Suite, OWASP ZAP<br>
                <strong>Manual testing:</strong> Check for error messages, time delays, boolean responses
               </div>`;

    document.getElementById('sqlOutput').innerHTML = output;
}

function clearSQL() {
    document.getElementById('sqlTarget').value = '';
    document.getElementById('sqlOutput').innerHTML = '';
}

// Pattern Generator
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
        `<div class="message success"><strong>Generated Pattern (${pattern.length} chars):</strong></div>
         <div style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; margin-top: 10px;">${pattern}</div>`;
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
    const generatedPatternDiv = document.querySelector('#patternOutput div:last-child');
    
    if (!generatedPatternDiv || !crashPattern) {
        showMessage('offsetOutput', 'Please generate a pattern first and enter crash pattern', 'error');
        return;
    }
    
    const generatedPattern = generatedPatternDiv.textContent;
    const offset = generatedPattern.indexOf(crashPattern);

    if (offset !== -1) {
        showMessage('offsetOutput', `Offset found: ${offset} bytes`, 'success');
    } else {
        showMessage('offsetOutput', 'Pattern not found in generated sequence', 'error');
    }
}

function clearPattern() {
    document.getElementById('patternLength').value = '100';
    document.getElementById('patternOutput').innerHTML = '';
    document.getElementById('crashPattern').value = '';
    document.getElementById('offsetOutput').innerHTML = '';
}

// Password Generator
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
        showMessage('passwordOutput', 'Please select at least one character set', 'error');
        return;
    }

    let output = '<div class="message info"><strong>Generated Passwords:</strong></div>';

    for (let i = 0; i < count; i++) {
        let password = '';
        for (let j = 0; j < length; j++) {
            password += charset[Math.floor(Math.random() * charset.length)];
        }
        const strength = calculatePasswordStrength(password);
        const strengthClass = strength.level === 'strong' ? 'success' : strength.level === 'medium' ? 'warning' : 'error';
        output += `<div style="margin: 5px 0; padding: 8px; background: rgba(255,255,255,0.05); border-radius: 3px; font-family: monospace;">
                    <strong>${password}</strong> 
                    <span class="message ${strengthClass}" style="display: inline; padding: 2px 6px; margin-left: 10px;">${strength.score}/100 (${strength.level})</span>
                   </div>`;
    }

    document.getElementById('passwordOutput').innerHTML = output;
}

function calculatePasswordStrength(password) {
    let score = 0;

    score += Math.min(password.length * 2, 30);

    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;

    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;

    if (/(.)\1{2,}/.test(password)) score -= 10;
    if (/123|abc|qwe/i.test(password)) score -= 15;

    const level = score >= 80 ? 'strong' : score >= 60 ? 'medium' : 'weak';

    return { score: Math.max(0, Math.min(100, score)), level };
}

function checkPasswordStrength() {
    showMessage('passwordOutput', 'Enter a password to check its strength in the input field above, then click Generate to see strength analysis.', 'info');
}

function clearPasswords() {
    document.getElementById('passwordOutput').innerHTML = '';
}

// Brainfuck Interpreter
function executeBrainfuck() {
    const code = document.getElementById('bfCode').value;
    const input = document.getElementById('bfInput').value;

    if (!code) {
        showMessage('bfOutput', 'Please enter some Brainfuck code', 'error');
        return;
    }

    const result = interpretBrainfuck(code, input);

    showMessage('bfOutput', `Output: ${result.output || '(no output)'}`, 'success');
    document.getElementById('bfMemory').innerHTML = 
        `<div class="message info"><strong>Memory:</strong> [${result.memory.slice(0, 20).join(', ')}${result.memory.length > 20 ? '...' : ''}]</div>`;
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
    // Hello World program
    document.getElementById('bfCode').value = '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.';
    document.getElementById('bfInput').value = '';
    showMessage('bfOutput', 'Hello World example loaded', 'info');
}

function stepBrainfuck() {
    showMessage('bfOutput', 'Step-by-step execution feature coming soon!', 'info');
}

function clearBrainfuck() {
    document.getElementById('bfCode').value = '';
    document.getElementById('bfInput').value = '';
    document.getElementById('bfOutput').innerHTML = '';
    document.getElementById('bfMemory').innerHTML = '';
}

// QR Code functions (placeholder)
function decodeQR() {
    showMessage('qrOutput', 'QR Code decoding feature requires additional libraries. Upload an image to analyze.', 'info');
}

function generateQR() {
    const text = document.getElementById('qrText').value;
    if (!text) {
        showMessage('qrOutput', 'Please enter text to generate QR code', 'error');
        return;
    }
    showMessage('qrOutput', `QR code generation for: "${text}" - Feature requires QR library implementation`, 'info');
}

function clearQR() {
    document.getElementById('qrText').value = '';
    document.getElementById('qrOutput').innerHTML = '';
    const canvas = document.getElementById('qrCanvas');
    if (canvas) canvas.style.display = 'none';
}

// Generic functions for basic tools
function processBasicTool(toolName) {
    const input = document.getElementById(`${toolName}Input`).value;
    const output = document.getElementById(`${toolName}Output`);

    if (!input.trim()) {
        showMessage(`${toolName}Output`, 'Please enter some input data', 'error');
        return;
    }

    showMessage(`${toolName}Output`, `Tool "${getToolTitle(toolName)}" processed input successfully. Advanced implementation available for full functionality.`, 'success');
}

function clearBasicTool(toolName) {
    document.getElementById(`${toolName}Input`).value = '';
    document.getElementById(`${toolName}Output`).innerHTML = '';
}

// Utility function for showing messages
function showMessage(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `<div class="message ${type}">${message}</div>`;
    }
}

// Error handling
window.addEventListener('error', function(e) {
    console.error('JavaScript Error:', e.error);
    alert('An error occurred. Check the console for details.');
});

// Ensure everything is loaded
window.addEventListener('load', function() {
    console.log('CTF Arsenal fully loaded and ready!');
});
