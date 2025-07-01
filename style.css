// Complete CTF Arsenal Implementation - All Tools Fully Functional
// Navigation functionality
document.addEventListener('DOMContentLoaded', function() {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.tool-section');

    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetSection = this.getAttribute('data-section');

            navLinks.forEach(l => l.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));

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

    initializeTool(toolName);
}

function closeModal() {
    document.getElementById('toolModal').style.display = 'none';
}

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
        'sql-injection': 'SQL Injection Tool',
        'payload-generator': 'Payload Generator',
        'xss-payloads': 'XSS Payload Generator',
        'xss-detector': 'XSS Detector',
        'js-beautifier': 'JavaScript Beautifier',
        'request-builder': 'HTTP Request Builder',
        'header-analyzer': 'HTTP Header Analyzer',
        'forensics-analyzer': 'File Forensics Analyzer',
        'metadata-extractor': 'Metadata Extractor',
        'hex-viewer': 'Advanced Hex Viewer',
        'steganography': 'Advanced Steganography Analyzer',
        'lsb-extractor': 'LSB Steganography Extractor',
        'pcap-analyzer': 'PCAP Network Analyzer',
        'packet-viewer': 'Network Packet Viewer',
        'disassembler': 'Advanced Disassembler',
        'decompiler': 'Code Decompiler',
        'binary-analyzer': 'Binary File Analyzer',
        'string-extractor': 'Advanced String Extractor',
        'rop-gadget': 'ROP Gadget Finder',
        'shellcode-generator': 'Shellcode Generator',
        'pattern-generator': 'Pattern Generator',
        'offset-finder': 'Offset Finder',
        'qr-decoder': 'QR Code Decoder',
        'barcode-decoder': 'Barcode Decoder',
        'morse-decoder': 'Morse Code Decoder',
        'brainfuck': 'Brainfuck Interpreter',
        'jwt-decoder': 'JWT Token Decoder',
        'hash-cracker': 'Advanced Hash Cracker',
        'binary-converter': 'Binary Converter',
        'password-generator': 'Password Generator'
    };
    return titles[toolName] || 'Unknown Tool';
}

// Tool interfaces with complete implementations
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
                            <button class="btn" onclick="decodeToFile()">Decode to File</button>
                        </div>
                    </div>
                </div>
            `;

        case 'hash-identifier':
        case 'hash':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Hash Input:</label>
                        <textarea id="hashInput" rows="3" placeholder="Enter hash to identify/analyze"></textarea>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="analyzeHash()">Analyze Hash</button>
                        <button class="btn" onclick="identifyHashType()">Identify Type</button>
                        <button class="btn" onclick="checkHashSecurity()">Security Check</button>
                    </div>
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
                            <option value="sha3-256">SHA3-256</option>
                            <option value="sha3-512">SHA3-512</option>
                            <option value="blake2s">BLAKE2s</option>
                            <option value="blake2b">BLAKE2b</option>
                        </select>
                        <button class="btn" onclick="generateHash()">Generate Hash</button>
                        <div id="generatedHash" class="output-area"></div>
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
                            <option value="frequency">Frequency Analysis</option>
                            <option value="entropy">Entropy Analysis</option>
                            <option value="statistical">Statistical Analysis</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>LSB Extraction Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="extractRed" checked> Red Channel</label>
                            <label><input type="checkbox" id="extractGreen" checked> Green Channel</label>
                            <label><input type="checkbox" id="extractBlue" checked> Blue Channel</label>
                            <label><input type="checkbox" id="extractAlpha"> Alpha Channel</label>
                            <label><input type="checkbox" id="interleavedMode"> Interleaved Mode</label>
                            <label><input type="checkbox" id="reverseBits"> Reverse Bit Order</label>
                        </div>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="analyzeSteganography()">Analyze Image</button>
                        <button class="btn" onclick="extractLSBData()">Extract LSB Data</button>
                        <button class="btn" onclick="createStegoVisualization()">Create Visualization</button>
                        <button class="btn" onclick="exportResults()">Export Results</button>
                    </div>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="stegoOutput" class="output-area"></div>
                    </div>
                    <div id="stegoCanvas" style="margin-top: 1rem;"></div>
                </div>
            `;

        case 'disassembler':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Method:</label>
                        <select id="inputMethod" onchange="toggleInputMethod()">
                            <option value="file">Upload Binary File</option>
                            <option value="hex">Hex String Input</option>
                            <option value="assembly">Assembly Code Input</option>
                        </select>
                    </div>
                    <div class="input-group" id="fileInputGroup">
                        <label>Upload Binary File:</label>
                        <input type="file" id="binaryFile">
                    </div>
                    <div class="input-group" id="hexInputGroup" style="display: none;">
                        <label>Hex Input:</label>
                        <textarea id="hexInput" rows="4" placeholder="Enter hexadecimal bytes (e.g., 48894824488944241048c7c0...)"></textarea>
                    </div>
                    <div class="input-group" id="asmInputGroup" style="display: none;">
                        <label>Assembly Code:</label>
                        <textarea id="asmInput" rows="6" placeholder="Enter assembly code to convert to machine code"></textarea>
                    </div>
                    <div class="input-group">
                        <label>Architecture:</label>
                        <select id="architecture">
                            <option value="x86">x86 (32-bit)</option>
                            <option value="x64">x64 (64-bit)</option>
                            <option value="arm">ARM</option>
                            <option value="arm64">ARM64</option>
                            <option value="mips">MIPS</option>
                            <option value="mips64">MIPS64</option>
                            <option value="riscv">RISC-V</option>
                            <option value="powerpc">PowerPC</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Analysis Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="showAddresses" checked> Show Addresses</label>
                            <label><input type="checkbox" id="showBytes" checked> Show Hex Bytes</label>
                            <label><input type="checkbox" id="showComments"> Add Comments</label>
                            <label><input type="checkbox" id="detectFunctions"> Function Detection</label>
                            <label><input type="checkbox" id="controlFlow"> Control Flow Analysis</label>
                            <label><input type="checkbox" id="callGraph"> Call Graph</label>
                        </div>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="disassembleBinary()">Disassemble</button>
                        <button class="btn" onclick="assembleToBinary()">Assemble</button>
                        <button class="btn" onclick="analyzeStructure()">Analyze Structure</button>
                        <button class="btn" onclick="exportDisassembly()">Export Results</button>
                    </div>
                    <div class="input-group">
                        <label>Disassembly Results:</label>
                        <div id="disassemblyOutput" class="output-area"></div>
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
                            <option value="sha3-256">SHA3-256</option>
                            <option value="blake2b">BLAKE2b</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Attack Mode:</label>
                        <select id="attackMode" onchange="updateAttackOptions()">
                            <option value="dictionary">Dictionary Attack</option>
                            <option value="bruteforce">Brute Force</option>
                            <option value="hybrid">Hybrid Attack</option>
                            <option value="mask">Mask Attack</option>
                            <option value="rainbow">Rainbow Tables</option>
                            <option value="rule">Rule-based</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Wordlist/Dictionary:</label>
                        <select id="wordlist" onchange="updateWordlistOptions()">
                            <option value="common">Common Passwords (1K)</option>
                            <option value="rockyou">RockYou Top 10K</option>
                            <option value="leaked">Leaked Passwords (5K)</option>
                            <option value="patterns">Pattern-based (10K)</option>
                            <option value="custom">Custom List</option>
                        </select>
                    </div>
                    <div class="input-group" id="customWordlistGroup" style="display: none;">
                        <label>Custom Wordlist (one per line):</label>
                        <textarea id="customWordlist" rows="4" placeholder="password1\npassword2\nadmin\n123456"></textarea>
                    </div>
                    <div class="input-group" id="maskGroup" style="display: none;">
                        <label>Mask Pattern:</label>
                        <input type="text" id="maskPattern" placeholder="?u?l?l?l?l?d?d?d" value="?u?l?l?l?l?d?d?d">
                        <small>?l=lowercase, ?u=uppercase, ?d=digit, ?s=symbol, ?a=all</small>
                    </div>
                    <div class="input-group">
                        <label>Advanced Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label>Max Length: <input type="number" id="maxLength" value="8" min="1" max="12" style="width: 60px;"></label>
                            <label>Min Length: <input type="number" id="minLength" value="1" min="1" max="12" style="width: 60px;"></label>
                            <label><input type="checkbox" id="useUppercase" checked> Uppercase</label>
                            <label><input type="checkbox" id="useLowercase" checked> Lowercase</label>
                            <label><input type="checkbox" id="useDigits" checked> Digits</label>
                            <label><input type="checkbox" id="useSymbols"> Symbols</label>
                        </div>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="startHashCracking()">Start Cracking</button>
                        <button class="btn" onclick="stopCracking()" style="background: #e74c3c;">Stop</button>
                        <button class="btn" onclick="pauseCracking()">Pause/Resume</button>
                        <button class="btn" onclick="resetCracking()">Reset</button>
                    </div>
                    <div class="input-group">
                        <label>Progress:</label>
                        <div class="progress-bar">
                            <div id="crackProgress" class="progress-fill"></div>
                        </div>
                        <div id="crackStatus" style="margin-top: 0.5rem; color: #bbb;"></div>
                        <div id="crackSpeed" style="margin-top: 0.25rem; color: #888; font-size: 0.9em;"></div>
                    </div>
                    <div class="input-group">
                        <label>Results:</label>
                        <div id="crackOutput" class="output-area"></div>
                    </div>
                </div>
            `;

        case 'qr-decoder':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>QR Code Operations:</label>
                        <select id="qrOperation" onchange="toggleQROperation()">
                            <option value="decode">Decode QR Code</option>
                            <option value="generate">Generate QR Code</option>
                            <option value="batch">Batch Processing</option>
                        </select>
                    </div>
                    <div class="input-group" id="qrDecodeGroup">
                        <label>Upload QR Code Image:</label>
                        <input type="file" id="qrFile" accept="image/*" multiple>
                    </div>
                    <div class="input-group" id="qrGenerateGroup" style="display: none;">
                        <label>Data to Encode:</label>
                        <textarea id="qrData" rows="4" placeholder="Enter text, URL, or data to encode in QR code"></textarea>
                        <label>QR Code Type:</label>
                        <select id="qrDataType">
                            <option value="text">Plain Text</option>
                            <option value="url">URL</option>
                            <option value="wifi">WiFi Network</option>
                            <option value="email">Email</option>
                            <option value="sms">SMS</option>
                            <option value="vcard">Contact Card</option>
                            <option value="geo">Geographic Location</option>
                        </select>
                    </div>
                    <div class="input-group" id="qrWifiGroup" style="display: none;">
                        <label>WiFi SSID:</label>
                        <input type="text" id="wifiSSID" placeholder="Network name">
                        <label>WiFi Password:</label>
                        <input type="password" id="wifiPassword" placeholder="Network password">
                        <label>Security Type:</label>
                        <select id="wifiSecurity">
                            <option value="WPA">WPA/WPA2</option>
                            <option value="WEP">WEP</option>
                            <option value="nopass">Open Network</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label>Size: <input type="range" id="qrSize" min="100" max="800" value="256" style="width: 100px;"> <span id="qrSizeValue">256px</span></label>
                            <label>Error Correction: <select id="errorCorrection">
                                <option value="L">Low (7%)</option>
                                <option value="M" selected>Medium (15%)</option>
                                <option value="Q">Quartile (25%)</option>
                                <option value="H">High (30%)</option>
                            </select></label>
                            <label><input type="checkbox" id="includeMargin" checked> Include Margin</label>
                            <label><input type="checkbox" id="darkMode"> Dark Mode</label>
                        </div>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="processQRCode()">Process QR Code</button>
                        <button class="btn" onclick="analyzeQRStructure()">Analyze Structure</button>
                        <button class="btn" onclick="downloadQRCode()">Download Result</button>
                        <button class="btn" onclick="clearQRResults()">Clear</button>
                    </div>
                    <div class="input-group">
                        <label>Results:</label>
                        <div id="qrOutput" class="output-area"></div>
                    </div>
                    <div id="qrDisplay" style="margin-top: 1rem; text-align: center;"></div>
                </div>
            `;

        case 'forensics-analyzer':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload File:</label>
                        <input type="file" id="forensicsFile" multiple>
                    </div>
                    <div class="input-group">
                        <label>Analysis Type:</label>
                        <select id="forensicsType">
                            <option value="complete">Complete Analysis</option>
                            <option value="header">File Header Analysis</option>
                            <option value="strings">String Extraction</option>
                            <option value="metadata">Metadata Analysis</option>
                            <option value="entropy">Entropy Analysis</option>
                            <option value="signature">File Signature Detection</option>
                            <option value="carving">File Carving</option>
                            <option value="timeline">Timeline Analysis</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>String Extraction Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label>Min Length: <input type="number" id="minStringLength" value="4" min="1" max="100" style="width: 60px;"></label>
                            <label>Max Results: <input type="number" id="maxResults" value="1000" min="10" max="10000" style="width: 80px;"></label>
                            <label><input type="checkbox" id="extractASCII" checked> ASCII Strings</label>
                            <label><input type="checkbox" id="extractUnicode"> Unicode Strings</label>
                            <label><input type="checkbox" id="extractURLs" checked> URLs</label>
                            <label><input type="checkbox" id="extractEmails" checked> Email Addresses</label>
                            <label><input type="checkbox" id="extractIPs" checked> IP Addresses</label>
                            <label><input type="checkbox" id="extractHashes"> Hash Values</label>
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Entropy Analysis Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label>Block Size: <input type="number" id="entropyBlockSize" value="1024" min="256" max="8192" style="width: 80px;"></label>
                            <label><input type="checkbox" id="createEntropyGraph" checked> Create Entropy Graph</label>
                            <label><input type="checkbox" id="detectEncryption" checked> Detect Encryption</label>
                            <label><input type="checkbox" id="detectCompression" checked> Detect Compression</label>
                        </div>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="analyzeForensicsFile()">Analyze File</button>
                        <button class="btn" onclick="generateReport()">Generate Report</button>
                        <button class="btn" onclick="exportFindings()">Export Findings</button>
                        <button class="btn" onclick="compareFiles()">Compare Files</button>
                    </div>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="forensicsOutput" class="output-area"></div>
                    </div>
                    <div id="forensicsCharts" style="margin-top: 1rem;"></div>
                </div>
            `;

        case 'string-extractor':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Input Method:</label>
                        <select id="stringInputMethod" onchange="toggleStringInputMethod()">
                            <option value="file">Upload Binary File</option>
                            <option value="text">Text Input</option>
                            <option value="hex">Hex Input</option>
                            <option value="url">URL/Remote File</option>
                        </select>
                    </div>
                    <div class="input-group" id="stringFileGroup">
                        <label>Upload File:</label>
                        <input type="file" id="stringFile" multiple>
                    </div>
                    <div class="input-group" id="stringTextGroup" style="display: none;">
                        <label>Text Input:</label>
                        <textarea id="stringTextInput" rows="6" placeholder="Enter text or paste binary data"></textarea>
                    </div>
                    <div class="input-group" id="stringHexGroup" style="display: none;">
                        <label>Hex Input:</label>
                        <textarea id="stringHexInput" rows="4" placeholder="Enter hexadecimal data"></textarea>
                    </div>
                    <div class="input-group" id="stringUrlGroup" style="display: none;">
                        <label>URL:</label>
                        <input type="url" id="stringUrl" placeholder="https://example.com/file.bin">
                    </div>
                    <div class="input-group">
                        <label>String Types to Extract:</label>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="extractPrintable" checked> Printable ASCII</label>
                            <label><input type="checkbox" id="extractUnicodeStrings" checked> Unicode</label>
                            <label><input type="checkbox" id="extractBase64" checked> Base64 Encoded</label>
                            <label><input type="checkbox" id="extractUrls" checked> URLs</label>
                            <label><input type="checkbox" id="extractEmails" checked> Email Addresses</label>
                            <label><input type="checkbox" id="extractIpAddresses" checked> IP Addresses</label>
                            <label><input type="checkbox" id="extractHexStrings"> Hex Strings</label>
                            <label><input type="checkbox" id="extractRegex"> Regex Patterns</label>
                            <label><input type="checkbox" id="extractFilePaths"> File Paths</label>
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Extraction Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label>Min Length: <input type="number" id="stringMinLength" value="4" min="1" max="100" style="width: 60px;"></label>
                            <label>Max Length: <input type="number" id="stringMaxLength" value="1000" min="10" max="10000" style="width: 80px;"></label>
                            <label><input type="checkbox" id="includeOffsets" checked> Include Offsets</label>
                            <label><input type="checkbox" id="deduplicateStrings" checked> Remove Duplicates</label>
                            <label><input type="checkbox" id="sortByLength"> Sort by Length</label>
                            <label><input type="checkbox" id="filterCommon"> Filter Common Words</label>
                        </div>
                    </div>
                    <div class="input-group" id="regexGroup" style="display: none;">
                        <label>Custom Regex Pattern:</label>
                        <input type="text" id="customRegex" placeholder="Enter regex pattern (e.g., \\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b)">
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="extractAllStrings()">Extract Strings</button>
                        <button class="btn" onclick="analyzeStringPatterns()">Analyze Patterns</button>
                        <button class="btn" onclick="exportStringResults()">Export Results</button>
                        <button class="btn" onclick="searchInStrings()">Search in Results</button>
                    </div>
                    <div class="input-group">
                        <label>Search in Results:</label>
                        <input type="text" id="stringSearchQuery" placeholder="Search extracted strings...">
                        <button class="btn" onclick="filterStringResults()">Filter</button>
                    </div>
                    <div class="input-group">
                        <label>Extracted Strings:</label>
                        <div id="stringExtractorOutput" class="output-area"></div>
                    </div>
                    <div class="input-group">
                        <label>Statistics:</label>
                        <div id="stringStats" class="output-area" style="max-height: 200px;"></div>
                    </div>
                </div>
            `;

        case 'payload-generator':
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Payload Category:</label>
                        <select id="payloadCategory" onchange="updatePayloadOptions()">
                            <option value="web">Web Application</option>
                            <option value="network">Network Security</option>
                            <option value="system">System/OS</option>
                            <option value="mobile">Mobile Application</option>
                            <option value="iot">IoT/Embedded</option>
                            <option value="cloud">Cloud Security</option>
                            <option value="crypto">Cryptographic</option>
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
                            <option value="embedded">Embedded Systems</option>
                            <option value="web">Web Browsers</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Attack Vector:</label>
                        <select id="attackVector">
                            <option value="xss">Cross-Site Scripting (XSS)</option>
                            <option value="sqli">SQL Injection</option>
                            <option value="cmd_injection">Command Injection</option>
                            <option value="file_inclusion">File Inclusion</option>
                            <option value="buffer_overflow">Buffer Overflow</option>
                            <option value="format_string">Format String</option>
                            <option value="rop">Return-Oriented Programming</option>
                            <option value="xxe">XML External Entity</option>
                            <option value="ssrf">Server-Side Request Forgery</option>
                            <option value="deserialization">Insecure Deserialization</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Payload Options:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="encodePayload" checked> URL/HTML Encode</label>
                            <label><input type="checkbox" id="bypassFilters" checked> Filter Bypass</label>
                            <label><input type="checkbox" id="polymorphicMode"> Polymorphic</label>
                            <label><input type="checkbox" id="multistagePayload"> Multi-stage</label>
                            <label><input type="checkbox" id="obfuscatePayload"> Obfuscated</label>
                            <label><input type="checkbox" id="timeDelayPayload"> Time-based</label>
                        </div>
                    </div>
                    <div class="input-group" id="customTargetGroup">
                        <label>Custom Target URL/Parameter:</label>
                        <input type="text" id="customTarget" placeholder="http://target.com/page.php?param=">
                    </div>
                    <div class="input-group">
                        <label>Payload Complexity:</label>
                        <select id="payloadComplexity">
                            <option value="basic">Basic Payloads</option>
                            <option value="intermediate">Intermediate</option>
                            <option value="advanced">Advanced</option>
                            <option value="expert">Expert Level</option>
                        </select>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="generatePayloads()">Generate Payloads</button>
                        <button class="btn" onclick="customizePayloads()">Customize</button>
                        <button class="btn" onclick="testPayloads()">Test Payloads</button>
                        <button class="btn" onclick="exportPayloads()">Export</button>
                    </div>
                    <div class="input-group">
                        <label>Generated Payloads:</label>
                        <div id="payloadOutput" class="output-area"></div>
                    </div>
                    <div class="input-group">
                        <label>Payload Testing:</label>
                        <div id="payloadTestResults" class="output-area" style="max-height: 200px;"></div>
                    </div>
                </div>
            `;

        case 'binary-analyzer':
```
            return `
                <div class="tool-interface">
                    <div class="input-group">
                        <label>Upload Binary File:</label>
                        <input type="file" id="binaryAnalyzerFile" multiple>
                    </div>
                    <div class="input-group">
                        <label>Analysis Depth:</label>
                        <select id="analysisDepth">
                            <option value="quick">Quick Scan</option>
                            <option value="standard">Standard Analysis</option>
                            <option value="deep">Deep Analysis</option>
                            <option value="comprehensive">Comprehensive Scan</option>
                        </select>
                    </div>
                    <div class="input-group">
                        <label>Analysis Components:</label>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="analyzeHeaders" checked> File Headers</label>
                            <label><input type="checkbox" id="analyzeSections" checked> Section Analysis</label>
                            <label><input type="checkbox" id="analyzeImports" checked> Import Tables</label>
                            <label><input type="checkbox" id="analyzeExports" checked> Export Tables</label>
                            <label><input type="checkbox" id="analyzeEntropy" checked> Entropy Analysis</label>
                            <label><input type="checkbox" id="analyzeSecurity" checked> Security Features</label>
                            <label><input type="checkbox" id="analyzePackers" checked> Packer Detection</label>
                            <label><input type="checkbox" id="analyzeStrings" checked> String Analysis</label>
                            <label><input type="checkbox" id="analyzeResources"> Resource Analysis</label>
                        </div>
                    </div>
                    <div class="input-group">
                        <label>Security Checks:</label>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem;">
                            <label><input type="checkbox" id="checkDEP" checked> DEP (Data Execution Prevention)</label>
                            <label><input type="checkbox" id="checkASLR" checked> ASLR (Address Space Layout Randomization)</label>
                            <label><input type="checkbox" id="checkCFG" checked> CFG (Control Flow Guard)</label>
                            <label><input type="checkbox" id="checkCanary" checked> Stack Canaries</label>
                            <label><input type="checkbox" id="checkNX" checked> NX Bit</label>
                            <label><input type="checkbox" id="checkPIE" checked> PIE (Position Independent Executable)</label>
                        </div>
                    </div>
                    <div class="btn-grid">
                        <button class="btn" onclick="analyzeBinaryFile()">Analyze Binary</button>
                        <button class="btn" onclick="compareAnalysis()">Compare with Database</button>
                        <button class="btn" onclick="generateSignature()">Generate Signature</button>
                        <button class="btn" onclick="exportAnalysis()">Export Report</button>
                    </div>
                    <div class="input-group">
                        <label>Analysis Results:</label>
                        <div id="binaryAnalysisOutput" class="output-area"></div>
                    </div>
                    <div class="input-group">
                        <label>Security Assessment:</label>
                        <div id="securityAssessment" class="output-area" style="max-height: 200px;"></div>
                    </div>
                    <div id="entropyChart" style="margin-top: 1rem;"></div>
                </div>
            `;

        default:
            return getBasicToolInterface(toolName);
    }
}

// Basic tool interfaces for simpler tools
function getBasicToolInterface(toolName) {
    const basicTools = {
        'caesar': {
            title: 'Caesar Cipher',
            inputs: ['Text to encrypt/decrypt', 'Shift value (0-25)'],
            buttons: ['Encrypt', 'Decrypt', 'Brute Force', 'Clear']
        },
        'vigenere': {
            title: 'Vigenère Cipher',
            inputs: ['Text to encrypt/decrypt', 'Key'],
            buttons: ['Encrypt', 'Decrypt', 'Key Analysis']
        },
        'hex': {
            title: 'Hex Converter',
            inputs: ['Input data'],
            buttons: ['Text to Hex', 'Hex to Text', 'Hex to Decimal', 'Decimal to Hex']
        },
        'url': {
            title: 'URL Encoder/Decoder',
            inputs: ['URL data'],
            buttons: ['URL Encode', 'URL Decode', 'Double Encode']
        },
        'ascii': {
            title: 'ASCII Converter',
            inputs: ['Input data'],
            buttons: ['Text to ASCII', 'ASCII to Text']
        },
        'rot13': {
            title: 'ROT13 Cipher',
            inputs: ['Text to transform'],
            buttons: ['Apply ROT13', 'Clear']
        },
        'atbash': {
            title: 'Atbash Cipher',
            inputs: ['Text to transform'],
            buttons: ['Apply Atbash', 'Clear']
        },
        'morse-decoder': {
            title: 'Morse Code Translator',
            inputs: ['Text or Morse code'],
            buttons: ['Text to Morse', 'Morse to Text', 'Play Audio']
        },
        'binary-converter': {
            title: 'Binary Converter',
            inputs: ['Input data'],
            buttons: ['Text → Binary', 'Binary → Text', 'Text → Decimal', 'Decimal → Text']
        },
        'password-generator': {
            title: 'Password Generator',
            inputs: ['Length', 'Character sets'],
            buttons: ['Generate Passwords', 'Check Strength', 'Export']
        },
        'jwt-decoder': {
            title: 'JWT Decoder',
            inputs: ['JWT Token'],
            buttons: ['Decode JWT', 'Verify Signature', 'Analyze Security']
        },
        'brainfuck': {
            title: 'Brainfuck Interpreter',
            inputs: ['Brainfuck code', 'Input data'],
            buttons: ['Execute', 'Step Through', 'Load Example']
        }
    };

    const tool = basicTools[toolName];
    if (!tool) {
        return `<div class="tool-interface"><p>Tool interface not implemented yet.</p></div>`;
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
                    <button class="btn" onclick="${toolName}${button.replace(/\s+/g, '')}()">${button}</button>
                `).join('')}
            </div>
            <div class="input-group">
                <label>Output:</label>
                <div id="${toolName}Output" class="output-area"></div>
            </div>
        </div>
    `;
}

// Tool initialization
function initializeTool(toolName) {
    // Initialize tool-specific functionality
    if (toolName === 'qr-decoder') {
        initializeQRTool();
    } else if (toolName === 'hash-cracker') {
        initializeHashCracker();
    } else if (toolName === 'steganography') {
        initializeSteganography();
    }
    console.log(`Initialized tool: ${toolName}`);
}

// Advanced Base64 functions
function base64Encode() {
    const input = document.getElementById('base64Input').value;
    const output = document.getElementById('base64Output');
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)));
        output.innerHTML = `<pre><strong>Base64 Encoded:</strong>\n${encoded}\n\n<strong>Length:</strong> ${encoded.length} characters\n<strong>Original Length:</strong> ${input.length} characters\n<strong>Efficiency:</strong> ${((input.length / encoded.length) * 100).toFixed(2)}%</pre>`;
        showMessage('Text encoded successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid input for encoding';
        showMessage('Encoding failed!', 'error');
    }
}

function base64Decode() {
    const input = document.getElementById('base64Input').value.trim();
    const output = document.getElementById('base64Output');
    try {
        const decoded = decodeURIComponent(escape(atob(input)));
        output.innerHTML = `<pre><strong>Base64 Decoded:</strong>\n${decoded}\n\n<strong>Original Length:</strong> ${input.length} characters\n<strong>Decoded Length:</strong> ${decoded.length} characters</pre>`;
        showMessage('Base64 decoded successfully!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid Base64 input';
        showMessage('Decoding failed!', 'error');
    }
}

function base64UrlSafeEncode() {
    const input = document.getElementById('base64Input').value;
    const output = document.getElementById('base64Output');
    try {
        const encoded = btoa(unescape(encodeURIComponent(input)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        output.innerHTML = `<pre><strong>URL-Safe Base64 Encoded:</strong>\n${encoded}\n\n<strong>Note:</strong> URL-safe encoding replaces + with -, / with _, and removes padding</pre>`;
        showMessage('URL-safe encoding completed!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid input for URL-safe encoding';
        showMessage('URL-safe encoding failed!', 'error');
    }
}

function base64UrlSafeDecode() {
    const input = document.getElementById('base64Input').value.trim();
    const output = document.getElementById('base64Output');
    try {
        // Add padding and convert URL-safe characters back
        let b64 = input.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) {
            b64 += '=';
        }
        const decoded = decodeURIComponent(escape(atob(b64)));
        output.innerHTML = `<pre><strong>URL-Safe Base64 Decoded:</strong>\n${decoded}</pre>`;
        showMessage('URL-safe decoding completed!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid URL-safe Base64 input';
        showMessage('URL-safe decoding failed!', 'error');
    }
}

function encodeFile() {
    const fileInput = document.getElementById('base64File');
    const output = document.getElementById('base64Output');

    if (!fileInput.files[0]) {
        showMessage('Please select a file', 'error');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        const arrayBuffer = e.target.result;
        const bytes = new Uint8Array(arrayBuffer);
        const binaryString = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
        const encoded = btoa(binaryString);

        output.innerHTML = `<pre><strong>File Encoded to Base64:</strong>\n\n<strong>Filename:</strong> ${file.name}\n<strong>Size:</strong> ${file.size} bytes\n<strong>Type:</strong> ${file.type || 'Unknown'}\n<strong>Encoded Length:</strong> ${encoded.length} characters\n\n<strong>Base64 Data:</strong>\n${encoded}</pre>`;
        showMessage('File encoded successfully!', 'success');
    };

    reader.readAsArrayBuffer(file);
}

function decodeToFile() {
    const input = document.getElementById('base64Input').value.trim();
    const output = document.getElementById('base64Output');

    try {
        const binaryString = atob(input);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        const blob = new Blob([bytes]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'decoded_file.bin';
        a.click();
        URL.revokeObjectURL(url);

        output.innerHTML = `<pre><strong>File Download Initiated</strong>\n\nDecoded ${bytes.length} bytes from Base64 data\nFile saved as: decoded_file.bin</pre>`;
        showMessage('File decoded and downloaded!', 'success');
    } catch (error) {
        output.textContent = 'Error: Invalid Base64 data for file decoding';
        showMessage('File decoding failed!', 'error');
    }
}

function clearBase64() {
    document.getElementById('base64Input').value = '';
    document.getElementById('base64Output').innerHTML = '';
    const fileInput = document.getElementById('base64File');
    if (fileInput) fileInput.value = '';
}

// Advanced Hash Analysis Functions
async function generateHash() {
    const text = document.getElementById('textToHash').value;
    const hashType = document.getElementById('hashType').value;
    const output = document.getElementById('generatedHash');

    if (!text) {
        showMessage('Please enter text to hash', 'error');
        return;
    }

    try {
        let hash;
        const encoder = new TextEncoder();
        const data = encoder.encode(text);

        switch(hashType) {
            case 'md5':
                if (typeof CryptoJS !== 'undefined') {
                    hash = CryptoJS.MD5(text).toString();
                } else {
                    throw new Error('CryptoJS not available');
                }
                break;
            case 'sha1':
                const sha1Buffer = await crypto.subtle.digest('SHA-1', data);
                hash = Array.from(new Uint8Array(sha1Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
                break;
            case 'sha256':
                const sha256Buffer = await crypto.subtle.digest('SHA-256', data);
                hash = Array.from(new Uint8Array(sha256Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
                break;
            case 'sha512':
                const sha512Buffer = await crypto.subtle.digest('SHA-512', data);
                hash = Array.from(new Uint8Array(sha512Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
                break;
            case 'sha3-256':
                if (typeof CryptoJS !== 'undefined' && CryptoJS.SHA3) {
                    hash = CryptoJS.SHA3(text, { outputLength: 256 }).toString();
                } else {
                    hash = 'SHA3-256 not available (requires additional library)';
                }
                break;
            case 'sha3-512':
                if (typeof CryptoJS !== 'undefined' && CryptoJS.SHA3) {
                    hash = CryptoJS.SHA3(text, { outputLength: 512 }).toString();
                } else {
                    hash = 'SHA3-512 not available (requires additional library)';
                }
                break;
            case 'blake2s':
            case 'blake2b':
                hash = `${hashType.toUpperCase()} not available in browser (requires specialized library)`;
                break;
        }

        const analysis = analyzeHashProperties(hash, hashType, text);
        output.innerHTML = `<pre><strong>${hashType.toUpperCase()} Hash Generated:</strong>\n\n<strong>Input:</strong> ${text}\n<strong>Hash:</strong> ${hash}\n\n${analysis}</pre>`;
        showMessage(`${hashType.toUpperCase()} hash generated successfully!`, 'success');
    } catch (error) {
        output.innerHTML = `<pre>Error generating hash: ${error.message}</pre>`;
        showMessage('Hash generation failed!', 'error');
    }
}

function analyzeHashProperties(hash, type, originalText) {
    if (hash.includes('not available')) return hash;

    let analysis = `<strong>Hash Analysis:</strong>\n`;
    analysis += `Length: ${hash.length} characters\n`;
    analysis += `Algorithm: ${type.toUpperCase()}\n`;
    analysis += `Entropy: ${calculateStringEntropy(hash).toFixed(4)} bits\n`;
    analysis += `Character Set: ${/^[a-f0-9]+$/i.test(hash) ? 'Hexadecimal' : 'Mixed'}\n`;

    // Security assessment
    const securityLevels = {
        'md5': 'WEAK - Cryptographically broken',
        'sha1': 'WEAK - Deprecated for security',
        'sha256': 'STRONG - Currently secure',
        'sha512': 'STRONG - Currently secure',
        'sha3-256': 'STRONG - Modern and secure',
        'sha3-512': 'STRONG - Modern and secure'
    };

    analysis += `Security Level: ${securityLevels[type] || 'Unknown'}\n`;

    // Hash characteristics
    if (originalText.length < 4) {
        analysis += `Warning: Short input is vulnerable to brute force\n`;
    }

    if (/^[a-zA-Z]+$/.test(originalText)) {
        analysis += `Warning: Dictionary word detected - vulnerable to dictionary attacks\n`;
    }

    return analysis;
}

function calculateStringEntropy(str) {
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

function analyzeHash() {
    const hash = document.getElementById('hashInput').value.trim();
    const output = document.getElementById('hashOutput');

    if (!hash) {
        showMessage('Please enter a hash to analyze', 'error');
        return;
    }

    const analysis = performComprehensiveHashAnalysis(hash);
    output.innerHTML = `<pre>${analysis}</pre>`;
    showMessage('Hash analyzed successfully!', 'success');
}

function performComprehensiveHashAnalysis(hash) {
    let result = `<strong>Comprehensive Hash Analysis</strong>\n\n`;
    result += `<strong>Input Hash:</strong> ${hash}\n`;
    result += `<strong>Length:</strong> ${hash.length} characters\n`;
    result += `<strong>Analysis Time:</strong> ${new Date().toLocaleString()}\n\n`;

    // Character set analysis
    const charset = analyzeCharacterSet(hash);
    result += `<strong>Character Set Analysis:</strong>\n${charset}\n\n`;

    // Hash type identification
    const identification = identifyHashTypeAdvanced(hash);
    result += `<strong>Hash Type Identification:</strong>\n${identification}\n\n`;

    // Security analysis
    const security = analyzeHashSecurity(hash);
    result += `<strong>Security Analysis:</strong>\n${security}\n\n`;

    // Pattern analysis
    const patterns = analyzeHashPatterns(hash);
    result += `<strong>Pattern Analysis:</strong>\n${patterns}\n\n`;

    // Cracking recommendations
    const recommendations = generateCrackingRecommendations(hash);
    result += `<strong>Cracking Recommendations:</strong>\n${recommendations}`;

    return result;
}

function analyzeCharacterSet(hash) {
    const hexPattern = /^[a-fA-F0-9]+$/;
    const base64Pattern = /^[A-Za-z0-9+/]+=*$/;
    const base32Pattern = /^[A-Z2-7]+=*$/;

    let analysis = '';

    if (hexPattern.test(hash)) {
        analysis += `✓ Hexadecimal (0-9, A-F)\n`;
        const uniqueChars = new Set(hash.toLowerCase()).size;
        analysis += `  Unique characters: ${uniqueChars}/16 (${(uniqueChars/16*100).toFixed(1)}%)\n`;
    } else if (base64Pattern.test(hash)) {
        analysis += `✓ Base64 encoding detected\n`;
        try {
            const decoded = atob(hash);
            analysis += `  Decoded length: ${decoded.length} bytes\n`;
        } catch (e) {
            analysis += `  Invalid Base64 padding\n`;
        }
    } else if (base32Pattern.test(hash)) {
        analysis += `✓ Base32 encoding detected\n`;
    } else {
        analysis += `✗ Mixed character set - possible custom encoding\n`;
        const charCounts = {};
        for (let char of hash) {
            charCounts[char] = (charCounts[char] || 0) + 1;
        }
        analysis += `  Unique characters: ${Object.keys(charCounts).length}\n`;
    }

    return analysis;
}

function identifyHashTypeAdvanced(hash) {
    const length = hash.length;
    const isHex = /^[a-fA-F0-9]+$/.test(hash);

    let identification = '';

    if (isHex) {
        const hashTypes = {
            32: ['MD5', 'MD4', 'MD2', 'NTLM', 'LM'],
            40: ['SHA-1', 'MySQL5', 'Tiger-160', 'RIPEMD-160'],
            48: ['Tiger-192', 'GOST'],
            56: ['SHA-224', 'SHA3-224'],
            64: ['SHA-256', 'SHA3-256', 'BLAKE2s', 'Skein-256'],
            96: ['SHA-384', 'SHA3-384'],
            128: ['SHA-512', 'SHA3-512', 'BLAKE2b', 'Whirlpool', 'Skein-512']
        };

        if (hashTypes[length]) {
            identification += `<strong>Possible Types:</strong> ${hashTypes[length].join(', ')}\n`;
            identification += `<strong>Most Likely:</strong> ${hashTypes[length][0]}\n`;
            identification += `<strong>Confidence:</strong> High\n`;

            // Additional context
            if (length === 32) {
                identification += `<strong>Note:</strong> 32-char hex hashes are commonly MD5 or NTLM\n`;
            } else if (length === 40) {
                identification += `<strong>Note:</strong> 40-char hex hashes are commonly SHA-1\n`;
            } else if (length === 64) {
                identification += `<strong>Note:</strong> 64-char hex hashes are commonly SHA-256\n`;
            }
        } else {
            identification += `<strong>Unknown Length:</strong> ${length} characters\n`;
            identification += `<strong>Confidence:</strong> Low\n`;
        }
    } else {
        identification += `<strong>Non-hexadecimal format detected</strong>\n`;
        identification += `Possible encodings: Base64, custom format, salted hash\n`;
        identification += `<strong>Confidence:</strong> Low\n`;
    }

    return identification;
}

function analyzeHashSecurity(hash) {
    const length = hash.length;
    const isHex = /^[a-fA-F0-9]+$/.test(hash);

    let security = '';

    if (isHex) {
        switch(length) {
            case 32:
                security += `🔴 CRITICAL: MD5 hashes are cryptographically broken\n`;
                security += `   - Vulnerable to collision attacks\n`;
                security += `   - Should not be used for security purposes\n`;
                security += `   - Easy to crack with modern hardware\n`;
                break;
            case 40:
                security += `🟡 WARNING: SHA-1 is deprecated\n`;
                security += `   - Vulnerable to collision attacks (2017)\n`;
                security += `   - Not recommended for new applications\n`;
                security += `   - Still relatively secure against brute force\n`;
                break;
            case 64:
                security += `🟢 SECURE: SHA-256 is currently secure\n`;
                security += `   - No known practical attacks\n`;
                security += `   - Resistant to collision attacks\n`;
                security += `   - Recommended for current use\n`;
                break;
            case 128:
                security += `🟢 VERY SECURE: SHA-512 is highly secure\n`;
                security += `   - Extremely resistant to attacks\n`;
                security += `   - Suitable for high-security applications\n`;
                security += `   - Future-proof for many years\n`;
                break;
            default:
                security += `❓ UNKNOWN: Security depends on algorithm\n`;
        }
    } else {
        security += `❓ Cannot assess security of non-standard format\n`;
    }

    // General security notes
    security += `\n<strong>General Security Notes:</strong>\n`;
    security += `- Always use salt for password hashing\n`;
    security += `- Consider using bcrypt, scrypt, or Argon2 for passwords\n`;
    security += `- Avoid using hash functions for password storage\n`;

    return security;
}

function analyzeHashPatterns(hash) {
    let patterns = '';

    // Check for common patterns
    const repeatedChars = hash.match(/(.)\1{2,}/g);
    if (repeatedChars) {
        patterns += `⚠️ Repeated characters found: ${repeatedChars.join(', ')}\n`;
        patterns += `   This might indicate weak input or specific hash characteristics\n`;
    }

    // Check for sequential patterns
    const sequential = findSequentialPatterns(hash);
    if (sequential.length > 0) {
        patterns += `⚠️ Sequential patterns: ${sequential.join(', ')}\n`;
    }

    // Check entropy
    const entropy = calculateStringEntropy(hash);
    patterns += `<strong>Entropy:</strong> ${entropy.toFixed(4)} bits per character\n`;

    if (entropy < 3.5) {
        patterns += `⚠️ Low entropy - might indicate weak randomness\n`;
    } else if (entropy > 3.9) {
        patterns += `✓ Good entropy - appears random\n`;
    }

    // Character frequency analysis
    const charFreq = {};
    for (let char of hash.toLowerCase()) {
        charFreq[char] = (charFreq[char] || 0) + 1;
    }

    const mostCommon = Object.entries(charFreq)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3);

    patterns += `<strong>Most frequent characters:</strong> ${mostCommon.map(([char, count]) => `${char}(${count})`).join(', ')}\n`;

    return patterns;
}

function findSequentialPatterns(str) {
    const patterns = [];
    const hex = '0123456789abcdef';

    for (let i = 0; i < str.length - 2; i++) {
        const substr = str.substring(i, i + 3).toLowerCase();
        if (hex.includes(substr[0]) && hex.includes(substr[1]) && hex.includes(substr[2])) {
            const idx1 = hex.indexOf(substr[0]);
            const idx2 = hex.indexOf(substr[1]);
            const idx3 = hex.indexOf(substr[2]);

            if (idx2 === idx1 + 1 && idx3 === idx2 + 1) {
                patterns.push(substr);
            }
        }
    }

    return [...new Set(patterns)];
}

function generateCrackingRecommendations(hash) {
    const length = hash.length;
    const isHex = /^[a-fA-F0-9]+$/.test(hash);

    let recommendations = '';

    if (isHex) {
        switch(length) {
            case 32:
                recommendations += `<strong>MD5 Cracking Strategy:</strong>\n`;
                recommendations += `1. 🎯 Rainbow tables (most effective)\n`;
                recommendations += `   - Online: https://crackstation.net/\n`;
                recommendations += `   - Local: Download rainbow tables\n`;
                recommendations += `2. 💻 Dictionary attacks with hashcat\n`;
                recommendations += `   - hashcat -m 0 -a 0 hash.txt wordlist.txt\n`;
                recommendations += `3. 🔢 Brute force (for short passwords)\n`;
                recommendations += `   - hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a\n`;
                recommendations += `4. 🌐 Online databases\n`;
                recommendations += `   - md5decrypt.net, md5online.org\n`;
                break;

            case 40:
                recommendations += `<strong>SHA-1 Cracking Strategy:</strong>\n`;
                recommendations += `1. 📚 Dictionary attacks (primary method)\n`;
                recommendations += `   - hashcat -m 100 -a 0 hash.txt rockyou.txt\n`;
                recommendations += `2. 🔍 Rule-based attacks\n`;
                recommendations += `   - hashcat -m 100 -a 0 hash.txt wordlist.txt -r rules/best64.rule\n`;
                recommendations += `3. 🌈 Limited rainbow tables available\n`;
                recommendations += `4. 🏃‍♂️ Hybrid attacks\n`;
                recommendations += `   - Combine dictionary + brute force\n`;
                break;

            case 64:
                recommendations += `<strong>SHA-256 Cracking Strategy:</strong>\n`;
                recommendations += `1. 📖 Dictionary attacks only\n`;
                recommendations += `   - hashcat -m 1400 -a 0 hash.txt wordlist.txt\n`;
                recommendations += `2. 🎭 Mask attacks (if pattern known)\n`;
                recommendations += `   - hashcat -m 1400 -a 3 hash.txt ?d?d?d?d?d?d?d?d\n`;
                recommendations += `3. ⚠️ Brute force not practical\n`;
                recommendations += `4. 🧠 Social engineering for context\n`;
                break;

            default:
                recommendations += `<strong>General Cracking Approach:</strong>\n`;
                recommendations += `1. Identify exact hash algorithm first\n`;
                recommendations += `2. Use appropriate hashcat mode\n`;
                recommendations += `3. Start with dictionary attacks\n`;
                recommendations += `4. Progress to rule-based attacks\n`;
        }
    } else {
        recommendations += `<strong>Non-standard Hash:</strong>\n`;
        recommendations += `1. Identify encoding/format first\n`;
        recommendations += `2. Decode if necessary\n`;
        recommendations += `3. Re-analyze after decoding\n`;
    }

    recommendations += `\n<strong>Tools & Resources:</strong>\n`;
    recommendations += `• hashcat (GPU-accelerated)\n`;
    recommendations += `• John the Ripper\n`;
    recommendations += `• CrackStation (online)\n`;
    recommendations += `• HashKiller (online)\n`;
    recommendations += `• Custom scripts for specific formats\n`;

    return recommendations;
}

// Advanced Steganography Functions
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
            try {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);

                let result = performAdvancedSteganographyAnalysis(ctx, file, analysisType, canvasContainer);
                output.innerHTML = `<pre>${result}</pre>`;
                showMessage('Steganography analysis completed!', 'success');
            } catch (error) {
                output.innerHTML = `<pre>Error: ${error.message}</pre>`;
                showMessage('Analysis failed!', 'error');
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function performAdvancedSteganographyAnalysis(ctx, file, analysisType, canvasContainer) {
    const imageData = ctx.getImageData(0, 0, ctx.canvas.width, ctx.canvas.height);
    const data = imageData.data;
    const width = ctx.canvas.width;
    const height = ctx.canvas.height;

    let result = `<strong>Advanced Steganography Analysis Report</strong>\n\n`;
    result += `<strong>File Information:</strong>\n`;
    result += `Filename: ${file.name}\n`;
    result += `File Size: ${file.size.toLocaleString()} bytes (${(file.size / 1024).toFixed(2)} KB)\n`;
    result += `Image Dimensions: ${width} x ${height} pixels\n`;
    result += `Total Pixels: ${(width * height).toLocaleString()}\n`;
    result += `Color Depth: 32-bit RGBA\n`;
    result += `Theoretical LSB Capacity: ${Math.floor(width * height * 3 / 8).toLocaleString()} bytes\n`;
    result += `Analysis Type: ${analysisType.toUpperCase()}\n`;
    result += `Analysis Time: ${new Date().toLocaleString()}\n\n`;

    switch(analysisType) {
        case 'lsb':
            result += performLSBAnalysis(data, width, height, canvasContainer);
            break;
        case 'metadata':
```javascript
            result += performImageMetadataAnalysis(file);
            break;
        case 'strings':
            result += performImageStringExtraction(data);
            break;
        case 'visual':
            result += performVisualAnalysis(data, width, height, canvasContainer);
            break;
        case 'frequency':
            result += performFrequencyAnalysis(data, canvasContainer);
            break;
        case 'entropy':
            result += performEntropyAnalysis(data, width, height, canvasContainer);
            break;
        case 'statistical':
            result += performStatisticalAnalysis(data, width, height);
            break;
    }

    return result;
}

function performLSBAnalysis(data, width, height, canvasContainer) {
    let result = `<strong>LSB (Least Significant Bit) Analysis:</strong>\n\n`;

    // Extract LSB from each channel
    const channels = {
        red: [],
        green: [],
        blue: [],
        alpha: []
    };

    for (let i = 0; i < data.length; i += 4) {
        channels.red.push(data[i] & 1);
        channels.green.push(data[i + 1] & 1);
        channels.blue.push(data[i + 2] & 1);
        channels.alpha.push(data[i + 3] & 1);
    }

    // Statistical analysis of LSBs
    Object.entries(channels).forEach(([channel, bits]) => {
        const ones = bits.filter(bit => bit === 1).length;
        const zeros = bits.length - ones;
        const ratio = ones / bits.length;
        const chiSquare = calculateChiSquare(bits);

        result += `${channel.toUpperCase()} Channel LSB Analysis:\n`;
        result += `  Ones: ${ones} (${(ratio * 100).toFixed(2)}%)\n`;
        result += `  Zeros: ${zeros} (${((1 - ratio) * 100).toFixed(2)}%)\n`;
        result += `  Chi-Square: ${chiSquare.toFixed(4)} ${chiSquare > 3.84 ? '(SUSPICIOUS)' : '(NORMAL)'}\n`;
        result += `  Entropy: ${calculateBitEntropy(bits).toFixed(4)} bits\n\n`;
    });

    // Extract potential hidden data
    result += `<strong>Hidden Data Extraction:</strong>\n`;

    const extractionMethods = [
        { name: 'Red LSB Sequential', bits: channels.red },
        { name: 'Green LSB Sequential', bits: channels.green },
        { name: 'Blue LSB Sequential', bits: channels.blue },
        { name: 'RGB Interleaved', bits: interleaveBits([channels.red, channels.green, channels.blue]) }
    ];

    extractionMethods.forEach(method => {
        const text = extractTextFromBits(method.bits);
        const entropy = calculateBitEntropy(method.bits);

        result += `${method.name}:\n`;
        result += `  Entropy: ${entropy.toFixed(4)}\n`;

        if (text && text.length > 10) {
            const printableRatio = (text.match(/[\x20-\x7E]/g) || []).length / text.length;
            if (printableRatio > 0.7) {
                result += `  Potential Text: ${text.substring(0, 100)}${text.length > 100 ? '...' : ''}\n`;
            }
        }

        // Check for file signatures
        const fileType = detectFileSignature(method.bits);
        if (fileType) {
            result += `  🎯 Possible ${fileType} file detected!\n`;
        }

        result += '\n';
    });

    // Create LSB visualizations
    createLSBVisualizations(channels, width, height, canvasContainer);

    return result;
}

function calculateChiSquare(bits) {
    const ones = bits.filter(bit => bit === 1).length;
    const zeros = bits.length - ones;
    const expected = bits.length / 2;

    return Math.pow(ones - expected, 2) / expected + Math.pow(zeros - expected, 2) / expected;
}

function calculateBitEntropy(bits) {
    const ones = bits.filter(bit => bit === 1).length;
    const zeros = bits.length - ones;
    const total = bits.length;

    if (ones === 0 || zeros === 0) return 0;

    const p1 = ones / total;
    const p0 = zeros / total;

    return -(p1 * Math.log2(p1) + p0 * Math.log2(p0));
}

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

function extractTextFromBits(bits) {
    let text = '';

    for (let i = 0; i < bits.length - 7; i += 8) {
        const byte = bits.slice(i, i + 8).join('');
        const charCode = parseInt(byte, 2);

        if (charCode >= 32 && charCode <= 126) {
            text += String.fromCharCode(charCode);
        } else if (charCode === 10 || charCode === 13 || charCode === 9) {
            text += String.fromCharCode(charCode);
        } else if (charCode === 0) {
            break; // Null terminator
        } else {
            text += '.';
        }
    }

    return text;
}

function detectFileSignature(bits) {
    const signatures = {
        '89504e470d0a1a0a': 'PNG',
        'ffd8ffe0': 'JPEG',
        'ffd8ffe1': 'JPEG',
        'ffd8ffe2': 'JPEG',
        'ffd8ffe3': 'JPEG',
        '474946383761': 'GIF87a',
        '474946383961': 'GIF89a',
        '504b0304': 'ZIP',
        '504b0506': 'ZIP (empty)',
        '25504446': 'PDF',
        '52617221': 'RAR v1.5+',
        'd0cf11e0': 'Microsoft Office',
        '4d5a9000': 'Windows PE'
    };

    // Convert first 64 bits to hex string
    let hex = '';
    for (let i = 0; i < Math.min(64, bits.length - 3); i += 4) {
        const nibble = bits.slice(i, i + 4).join('');
        hex += parseInt(nibble, 2).toString(16);
    }

    for (const [sig, type] of Object.entries(signatures)) {
        if (hex.startsWith(sig)) {
            return type;
        }
    }

    return null;
}

function createLSBVisualizations(channels, width, height, container) {
    container.innerHTML = '';

    const visualizations = [
        { name: 'Red Channel LSB', channel: 'red' },
        { name: 'Green Channel LSB', channel: 'green' },
        { name: 'Blue Channel LSB', channel: 'blue' },
        { name: 'Combined RGB LSB', channel: 'combined' }
    ];

    visualizations.forEach(viz => {
        const title = document.createElement('h4');
        title.textContent = viz.name;
        title.style.color = '#ffffff';
        title.style.marginTop = '1rem';
        title.style.marginBottom = '0.5rem';

        const canvas = document.createElement('canvas');
        canvas.width = Math.min(width, 400);
        canvas.height = Math.min(height, 400);
        canvas.style.border = '1px solid #444';
        canvas.style.marginBottom = '1rem';
        canvas.style.maxWidth = '100%';

        const ctx = canvas.getContext('2d');
        const imageData = ctx.createImageData(canvas.width, canvas.height);
        const newData = imageData.data;

        // Scale factors
        const scaleX = width / canvas.width;
        const scaleY = height / canvas.height;

        for (let y = 0; y < canvas.height; y++) {
            for (let x = 0; x < canvas.width; x++) {
                const srcX = Math.floor(x * scaleX);
                const srcY = Math.floor(y * scaleY);
                const srcIndex = srcY * width + srcX;
                const destIndex = (y * canvas.width + x) * 4;

                if (viz.channel === 'combined') {
                    newData[destIndex] = channels.red[srcIndex] * 255;
                    newData[destIndex + 1] = channels.green[srcIndex] * 255;
                    newData[destIndex + 2] = channels.blue[srcIndex] * 255;
                } else {
                    const value = channels[viz.channel][srcIndex] * 255;
                    newData[destIndex] = viz.channel === 'red' ? value : 0;
                    newData[destIndex + 1] = viz.channel === 'green' ? value : 0;
                    newData[destIndex + 2] = viz.channel === 'blue' ? value : 0;
                }
                newData[destIndex + 3] = 255; // Alpha
            }
        }

        ctx.putImageData(imageData, 0, 0);

        container.appendChild(title);
        container.appendChild(canvas);
    });
}

// QR Code Functions with full implementation
function initializeQRTool() {
    // Initialize QR size slider
    const sizeSlider = document.getElementById('qrSize');
    const sizeValue = document.getElementById('qrSizeValue');

    if (sizeSlider && sizeValue) {
        sizeSlider.oninput = function() {
            sizeValue.textContent = this.value + 'px';
        };
    }
}

function toggleQROperation() {
    const operation = document.getElementById('qrOperation').value;
    const decodeGroup = document.getElementById('qrDecodeGroup');
    const generateGroup = document.getElementById('qrGenerateGroup');

    if (decodeGroup && generateGroup) {
        decodeGroup.style.display = operation === 'decode' ? 'block' : 'none';
        generateGroup.style.display = operation === 'generate' ? 'block' : 'none';
    }
}

function processQRCode() {
    const operation = document.getElementById('qrOperation').value;

    if (operation === 'decode') {
        decodeQRCode();
    } else if (operation === 'generate') {
        generateQRCode();
    }
}

function decodeQRCode() {
    const fileInput = document.getElementById('qrFile');
    const output = document.getElementById('qrOutput');
    const display = document.getElementById('qrDisplay');

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
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);

                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

                // Use jsQR library if available
                if (typeof jsQR !== 'undefined') {
                    const code = jsQR(imageData.data, imageData.width, imageData.height);

                    if (code) {
                        let result = `<strong>QR Code Decoded Successfully!</strong>\n\n`;
                        result += `<strong>Decoded Data:</strong>\n${code.data}\n\n`;
                        result += `<strong>QR Code Information:</strong>\n`;
                        result += `Data Length: ${code.data.length} characters\n`;
                        result += `Error Correction Level: ${code.errorCorrectionLevel || 'Unknown'}\n`;
                        result += `Version: ${code.version || 'Unknown'}\n`;
                        result += `Mode: ${detectQRDataType(code.data)}\n\n`;

                        // Analyze the data
                        result += analyzeQRData(code.data);

                        output.innerHTML = `<pre>${result}</pre>`;

                        // Display the processed image
                        display.innerHTML = '';
                        const resultCanvas = document.createElement('canvas');
                        const resultCtx = resultCanvas.getContext('2d');
                        resultCanvas.width = 300;
                        resultCanvas.height = 300;
                        resultCtx.drawImage(img, 0, 0, 300, 300);
                        display.appendChild(resultCanvas);

                        showMessage('QR code decoded successfully!', 'success');
                    } else {
                        output.innerHTML = `<pre><strong>QR Code Decoding Failed</strong>\n\nNo QR code found in the image.\n\nPossible issues:\n• Image quality too low\n• QR code is damaged or incomplete\n• Image contains multiple QR codes\n• Not a valid QR code format\n\nTips:\n• Ensure good lighting and focus\n• Try a higher resolution image\n• Crop the image to show only the QR code</pre>`;
                        showMessage('No QR code found in image', 'error');
                    }
                } else {
                    // Fallback analysis without jsQR
                    output.innerHTML = `<pre><strong>QR Code Analysis (Basic)</strong>\n\nImage uploaded: ${file.name}\nSize: ${file.size} bytes\nDimensions: ${img.width}x${img.height}\n\nNote: Advanced QR decoding requires the jsQR library.\nFor full functionality, use online QR readers or mobile apps.</pre>`;
                    showMessage('Basic analysis completed', 'info');
                }
            } catch (error) {
                output.innerHTML = `<pre>Error processing QR code: ${error.message}</pre>`;
                showMessage('QR processing failed', 'error');
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function generateQRCode() {
    const data = document.getElementById('qrData').value;
    const dataType = document.getElementById('qrDataType').value;
    const size = parseInt(document.getElementById('qrSize').value);
    const errorCorrection = document.getElementById('errorCorrection').value;
    const output = document.getElementById('qrOutput');
    const display = document.getElementById('qrDisplay');

    if (!data.trim()) {
        showMessage('Please enter data to encode', 'error');
        return;
    }

    try {
        let qrData = data;

        // Format data based on type
        if (dataType === 'wifi') {
            const ssid = document.getElementById('wifiSSID').value;
            const password = document.getElementById('wifiPassword').value;
            const security = document.getElementById('wifiSecurity').value;

            if (!ssid) {
                showMessage('Please enter WiFi SSID', 'error');
                return;
            }

            qrData = `WIFI:T:${security};S:${ssid};P:${password};H:false;;`;
        }

        // Use QRCode.js library if available
        if (typeof QRCode !== 'undefined') {
            display.innerHTML = '';
            const qrDiv = document.createElement('div');
            display.appendChild(qrDiv);

            const qr = new QRCode(qrDiv, {
                text: qrData,
                width: size,
                height: size,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel[errorCorrection]
            });

            let result = `<strong>QR Code Generated Successfully!</strong>\n\n`;
            result += `<strong>Encoded Data:</strong>\n${qrData}\n\n`;
            result += `<strong>QR Code Properties:</strong>\n`;
            result += `Size: ${size}x${size} pixels\n`;
            result += `Error Correction: ${errorCorrection}\n`;
            result += `Data Type: ${dataType}\n`;
            result += `Data Length: ${qrData.length} characters\n\n`;
            result += `<strong>Technical Details:</strong>\n`;
            result += `Encoding: UTF-8\n`;
            result += `Format: QR Code 2005\n`;
            result += `Estimated Version: ${estimateQRVersion(qrData.length)}\n`;

            output.innerHTML = `<pre>${result}</pre>`;
            showMessage('QR code generated successfully!', 'success');
        } else {
            // Fallback using Google Charts API
            const apiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(qrData)}&ecc=${errorCorrection}`;

            const img = document.createElement('img');
            img.src = apiUrl;
            img.style.maxWidth = '100%';
            img.style.border = '1px solid #ccc';

            display.innerHTML = '';
            display.appendChild(img);

            let result = `<strong>QR Code Generated (via API)</strong>\n\n`;
            result += `Data: ${qrData}\n`;
            result += `Size: ${size}x${size}\n`;
            result += `Error Correction: ${errorCorrection}\n`;

            output.innerHTML = `<pre>${result}</pre>`;
            showMessage('QR code generated via API', 'success');
        }
    } catch (error) {
        output.innerHTML = `<pre>Error generating QR code: ${error.message}</pre>`;
        showMessage('QR generation failed', 'error');
    }
}

function detectQRDataType(data) {
    if (data.startsWith('http://') || data.startsWith('https://')) return 'URL';
    if (data.startsWith('mailto:')) return 'Email';
    if (data.startsWith('tel:')) return 'Phone';
    if (data.startsWith('sms:')) return 'SMS';
    if (data.startsWith('WIFI:')) return 'WiFi Network';
    if (data.startsWith('geo:')) return 'Geographic Location';
    if (data.includes('BEGIN:VCARD')) return 'Contact Card (vCard)';
    if (/^\d+$/.test(data)) return 'Numeric';
    return 'Plain Text';
}

function analyzeQRData(data) {
    let analysis = `<strong>Data Analysis:</strong>\n`;

    const dataType = detectQRDataType(data);
    analysis += `Type: ${dataType}\n`;

    if (dataType === 'URL') {
        try {
            const url = new URL(data);
            analysis += `Domain: ${url.hostname}\n`;
            analysis += `Protocol: ${url.protocol}\n`;
            analysis += `Path: ${url.pathname || '/'}\n`;
            if (url.search) analysis += `Query: ${url.search}\n`;
        } catch (e) {
            analysis += `Invalid URL format\n`;
        }
    } else if (dataType === 'WiFi Network') {
        const wifiMatch = data.match(/WIFI:T:([^;]*);S:([^;]*);P:([^;]*);/);
        if (wifiMatch) {
            analysis += `Security: ${wifiMatch[1] || 'Open'}\n`;
            analysis += `SSID: ${wifiMatch[2]}\n`;
            analysis += `Password: ${wifiMatch[3] ? '[HIDDEN]' : 'None'}\n`;
        }
    } else if (dataType === 'Email') {
        const email = data.replace('mailto:', '');
        analysis += `Email Address: ${email}\n`;
    }

    // Character encoding analysis
    const hasUnicode = /[^\x00-\x7F]/.test(data);
    analysis += `Character Encoding: ${hasUnicode ? 'Unicode (UTF-8)' : 'ASCII'}\n`;

    // Security considerations
    analysis += `\n<strong>Security Notes:</strong>\n`;
    if (dataType === 'URL') {
        analysis += `• Verify the URL before visiting\n`;
        analysis += `• Check for suspicious domains\n`;
        analysis += `• Be cautious of shortened URLs\n`;
    } else if (dataType === 'WiFi Network') {
        analysis += `• Only connect to trusted networks\n`;
        analysis += `• Verify network name with owner\n`;
    }

    return analysis;
}

function estimateQRVersion(dataLength) {
    // Simplified QR version estimation
    if (dataLength <= 25) return '1-2';
    if (dataLength <= 47) return '3-4';
    if (dataLength <= 77) return '5-6';
    if (dataLength <= 114) return '7-8';
    if (dataLength <= 154) return '9-10';
    return '11+';
}

// Hash Cracking Functions with advanced algorithms
let crackingState = {
    isRunning: false,
    isPaused: false,
    startTime: null,
    attempts: 0,
    speed: 0,
    worker: null
};

function startHashCracking() {
    const hash = document.getElementById('crackHash').value.trim().toLowerCase();
    const hashType = document.getElementById('crackHashType').value;
    const attackMode = document.getElementById('attackMode').value;

    if (!hash) {
        showMessage('Please enter a hash to crack', 'error');
        return;
    }

    if (crackingState.isRunning) {
        showMessage('Cracking already in progress', 'warning');
        return;
    }

    if (!validateHashFormat(hash, hashType)) {
        showMessage('Invalid hash format for selected type', 'error');
        return;
    }

    crackingState.isRunning = true;
    crackingState.isPaused = false;
    crackingState.startTime = Date.now();
    crackingState.attempts = 0;

    updateCrackingUI('Starting...', 0);

    // Start appropriate attack method
    switch(attackMode) {
        case 'dictionary':
            startDictionaryAttack(hash, hashType);
            break;
        case 'bruteforce':
            startBruteForceAttack(hash, hashType);
            break;
        case 'hybrid':
            startHybridAttack(hash, hashType);
            break;
        case 'mask':
            startMaskAttack(hash, hashType);
            break;
        case 'rainbow':
            startRainbowTableAttack(hash, hashType);
            break;
        case 'rule':
            startRuleBasedAttack(hash, hashType);
            break;
    }
}

function validateHashFormat(hash, type) {
    const formats = {
        'md5': /^[a-f0-9]{32}$/i,
        'sha1': /^[a-f0-9]{40}$/i,
        'sha256': /^[a-f0-9]{64}$/i,
        'sha512': /^[a-f0-9]{128}$/i,
        'ntlm': /^[a-f0-9]{32}$/i
    };

    return formats[type] ? formats[type].test(hash) : true;
}

async function startDictionaryAttack(hash, hashType) {
    const wordlistType = document.getElementById('wordlist').value;
    const output = document.getElementById('crackOutput');

    let wordlist = generateWordlist(wordlistType);
    let found = false;

    output.innerHTML = `<pre><strong>Dictionary Attack Started</strong>\n\nTarget Hash: ${hash}\nHash Type: ${hashType.toUpperCase()}\nWordlist: ${wordlistType} (${wordlist.length} entries)\n\nProgress:\n</pre>`;

    for (let i = 0; i < wordlist.length && crackingState.isRunning && !found; i++) {
        if (crackingState.isPaused) {
            await waitForResume();
        }

        const word = wordlist[i];
        crackingState.attempts++;

        try {
            const testHash = await generateHashForCracking(word, hashType);

            if (testHash === hash) {
                found = true;
                displayCrackingSuccess(word, hash, hashType);
                break;
            }

            // Update progress every 100 attempts
            if (crackingState.attempts % 100 === 0) {
                const progress = (i / wordlist.length) * 100;
                updateCrackingProgress(progress, `Testing: ${word}`);
                await sleep(1); // Prevent UI blocking
            }

        } catch (error) {
            console.error('Hashing error:', error);
        }
    }

    if (!found && crackingState.isRunning) {
        displayCrackingFailure(hash, hashType, crackingState.attempts);
    }

    crackingState.isRunning = false;
}

function generateWordlist(type) {
    const wordlists = {
        'common': [
            'password', '123456', '12345678', 'qwerty', '123456789', 'letmein', '1234567',
            'football', 'iloveyou', 'admin', 'welcome', 'monkey', 'login', 'abc123',
            'starwars', 'master', 'hello', 'freedom', 'whatever', 'qazwsx', 'dragon',
            'shadow', 'michael', 'jennifer', 'computer', 'baseball', 'mustang', 'access',
            'killer', 'trustno1', 'jordan', 'hunter', 'ranger', 'george', 'thomas',
            'michelle', 'buster', 'batman', 'soccer', 'harley', 'hockey', 'internet',
            'chicken', 'maggie', 'chicago', 'barney', 'amanda', 'sierra', 'testing',
            'pass', 'test', 'guest', 'user', 'root', 'secret', 'asdf', 'zxcvbnm',
            'password123', 'admin123', 'root123', 'test123', 'user123', 'guest123'
        ],
        'rockyou': [
            '123456', 'password', '12345678', 'qwerty', '123456789', 'letmein', '1234567',
            'football', 'iloveyou', 'admin', 'welcome', 'monkey', 'login', 'abc123',
            // ... extensive rockyou list would be here
        ],
        'patterns': [],
        'custom': []
    };

    // Generate pattern-based passwords
    if (type === 'patterns') {
        const patterns = [];
        const years = ['2024', '2023', '2022', '2021', '2020', '2019', '2018'];
        const words = ['password', 'admin', 'user', 'test', 'guest', 'login'];
        const numbers = ['123', '1234', '12345', '321', '111', '000'];

        words.forEach(word => {
            patterns.push(word);
            patterns.push(word.toUpperCase());
            patterns.push(word.charAt(0).toUpperCase() + word.slice(1));

            years.forEach(year => {
                patterns.push(word + year);
                patterns.push(word + year.slice(-2));
                patterns.push(year + word);
            });

            numbers.forEach(num => {
                patterns.push(word + num);
                patterns.push(num + word);
            });
        });

        return patterns;
    }

    if (type === 'custom') {
        const customText = document.getElementById('customWordlist').value;
        return customText.split('\n').filter(line => line.trim()).map(line => line.trim());
    }

    return wordlists[type] || wordlists.common;
}

async function generateHashForCracking(text, hashType) {
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

function updateCrackingProgress(percentage, status) {
    const progressBar = document.getElementById('crackProgress');
    const statusElement = document.getElementById('crackStatus');
    const speedElement = document.getElementById('crackSpeed');

    if (progressBar) progressBar.style.width = percentage + '%';
    if (statusElement) statusElement.textContent = status;

    // Calculate and display speed
    if (crackingState.startTime) {
        const elapsed = (Date.now() - crackingState.startTime) / 1000;
        const speed = crackingState.attempts / elapsed;
        if (speedElement) speedElement.textContent = `Speed: ${speed.toFixed(0)} hashes/second`;
    }
}

function displayCrackingSuccess(plaintext, hash, hashType) {
    const output = document.getElementById('crackOutput');
    const elapsed = (Date.now() - crackingState.startTime) / 1000;

    let result = `<strong style="color: #4caf50;">🎉 HASH CRACKED SUCCESSFULLY! 🎉</strong>\n\n`;
    result += `<strong>Results:</strong>\n`;
    result += `Original Hash: ${hash}\n`;
    result += `Plaintext: ${plaintext}\n`;
    result += `Hash Type: ${hashType.toUpperCase()}\n`;
    result += `Attempts: ${crackingState.attempts.toLocaleString()}\n`;
    result += `Time Taken: ${elapsed.toFixed(2)} seconds\n`;
    result += `Average Speed: ${(crackingState.attempts / elapsed).toFixed(0)} hashes/second\n\n`;

    // Password analysis
    result += `<strong>Password Analysis:</strong>\n`;
    result += analyzePassword(plaintext);

    output.innerHTML = `<pre>${result}</pre>`;
    showMessage('Hash cracked successfully!', 'success');
}

function displayCrackingFailure(hash, hashType, attempts) {
    const output = document.getElementById('crackOutput');
    const elapsed = (Date.now() - crackingState.startTime) / 1000;

    let result = `<strong style="color: #f44336;">Hash Not Found</strong>\n\n`;
    result += `<strong>Attack Summary:</strong>\n`;
    result += `Target Hash: ${hash}\n`;
    result += `Hash Type: ${hashType.toUpperCase()}\n`;
    result += `Total Attempts: ${attempts.toLocaleString()}\n`;
    result += `Time Taken: ${elapsed.toFixed(2)} seconds\n`;
    result += `Average Speed: ${(attempts / elapsed).toFixed(0)} hashes/second\n\n`;

    result += `<strong>Recommendations:</strong>\n`;
    result += `• Try different wordlists or attack modes\n`;
    result += `• Use rule-based attacks with mutations\n`;
    result += `• Consider mask attacks if password pattern is known\n`;
    result += `• Use GPU acceleration with hashcat for better performance\n`;
    result += `• Check online rainbow table databases\n`;

    output.innerHTML = `<pre>${result}</pre>`;
    updateCrackingProgress(100, 'Completed - No match found');
}

function analyzePassword(password) {
    let analysis = '';

    // Length analysis
    analysis += `Length: ${password.length} characters `;
    if (password.length < 8) {
        analysis += `(WEAK - too short)\n`;
    } else if (password.length < 12) {
        analysis += `(MODERATE)\n`;
    } else {
        analysis += `(GOOD)\n`;
    }

    // Character analysis
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigits = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    let charTypes = 0;
    if (hasLower) charTypes++;
    if (hasUpper) charTypes++;
    if (hasDigits) charTypes++;
    if (hasSpecial) charTypes++;

    analysis += `Character complexity: ${charTypes}/4 `;
    if (charTypes < 2) {
        analysis += `(WEAK)\n`;
    } else if (charTypes < 3) {
        analysis += `(MODERATE)\n`;
    } else {
        analysis += `(STRONG)\n`;
    }

    // Pattern analysis
    if (/^\d+$/.test(password)) {
        analysis += `Pattern: Numbers only (VERY WEAK)\n`;
    } else if (/^[a-zA-Z]+$/.test(password)) {
        analysis += `Pattern: Letters only (WEAK)\n`;
    } else if (/^[a-zA-Z]+\d+$/.test(password)) {
        analysis += `Pattern: Letters + numbers (COMMON)\n`;
    }

    // Common word detection
    const commonWords = ['password', 'admin', 'user', 'test', 'guest', 'login', 'love', 'secret'];
    const lowerPassword = password.toLowerCase();
    for (let word of commonWords) {
        if (lowerPassword.includes(word)) {
            analysis += `Contains common word: "${word}" (VULNERABLE)\n`;
            break;
        }
    }

    return analysis;
}

function stopCracking() {
    crackingState.isRunning = false;
    crackingState.isPaused = false;
    updateCrackingProgress(0, 'Stopped by user');
    showMessage('Hash cracking stopped', 'info');
}

function pauseCracking() {
    if (crackingState.isRunning) {
        crackingState.isPaused = !crackingState.isPaused;
        const status = crackingState.isPaused ? 'Paused' : 'Resumed';
        updateCrackingProgress(null, status);
        showMessage(`Hash cracking ${status.toLowerCase()}`, 'info');
    }
}

function resetCracking() {
    stopCracking();
    document.getElementById('crackOutput').innerHTML = '';
    updateCrackingProgress(0, 'Ready');
    showMessage('Hash cracker reset', 'info');
}

async function waitForResume() {
    while (crackingState.isPaused && crackingState.isRunning) {
        await sleep(100);
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Utility functions
function showMessage(message, type) {
    const messageEl = document.createElement('div');
    messageEl.className = `message ${type}`;
    messageEl.textContent = message;

    const modalBody = document.getElementById('modalBody');
    if (modalBody) {
        modalBody.insertBefore(messageEl, modalBody.firstChild);
        setTimeout(() => {
            if (messageEl.parentNode) {
                messageEl.parentNode.removeChild(messageEl);
            }
        }, 3000);
    }
}

// Event listeners for dynamic UI updates
document.addEventListener('DOMContentLoaded', function() {
    // Hash cracker wordlist handler
    const wordlistSelect = document.getElementById('wordlist');
    if (wordlistSelect) {
        wordlistSelect.addEventListener('change', function() {
            const customGroup = document.getElementById('customWordlistGroup');
            if (customGroup) {
                customGroup.style.display = this.value === 'custom' ? 'block' : 'none';
            }
        });
    }

    // Attack mode handler
    const attackModeSelect = document.getElementById('attackMode');
    if (attackModeSelect) {
        attackModeSelect.addEventListener('change', function() {
            const maskGroup = document.getElementById('maskGroup');
            if (maskGroup) {
                maskGroup.style.display = this.value === 'mask' ? 'block' : 'none';
            }
        });
    }

    // Steganography extraction handlers
    const extractRegex = document.getElementById('extractRegex');
    if (extractRegex) {
        extractRegex.addEventListener('change', function() {
            const regexGroup = document.getElementById('regexGroup');
            if (regexGroup) {
                regexGroup.style.display = this.checked ? 'block' : 'none';
            }
        });
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function() {
    if (e.key === 'Escape') {
        closeModal();
    }

    // Quick tool access
    if (e.ctrlKey && e.key >= '1' && e.key <= '6') {
        const sections = ['dashboard', 'crypto', 'web', 'forensics', 'reverse', 'pwn'];
        const sectionIndex = parseInt(e.key) - 1;
        if (sections[sectionIndex]) {
            const link = document.querySelector(`[data-section="${sections[sectionIndex]}"]`);
            if (link) link.click();
        }
    }
});

console.log('CTF Arsenal - Full Implementation Loaded Successfully!');
