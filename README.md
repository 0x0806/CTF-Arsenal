
# 🛡️ CTF Arsenal - Ultimate Tool Dashboard

[![Live Demo](https://img.shields.io/badge/Live-Demo-blue?style=for-the-badge)](https://0x0806.github.io/CTF-Arsenal/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow?style=for-the-badge&logo=javascript)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/CSS)

> **A comprehensive web-based toolkit for Capture The Flag (CTF) competitions featuring 50+ specialized tools across 6 categories.**

![CTF Arsenal Dashboard](https://0x0806.github.io/CTF-Arsenal/)

## 🚀 Features

### 📊 Dashboard Overview
- **50+ Tools** across multiple categories
- **6 Specialized Categories** for different CTF challenges
- **Modern UI/UX** with dark theme and smooth animations
- **Responsive Design** - works on desktop, tablet, and mobile
- **Real-time Processing** with instant feedback

### 🔐 Cryptography Tools
- **Encoding/Decoding**: Base64, URL, Hex, ASCII converters
- **Classical Ciphers**: Caesar, Vigenère, Atbash, ROT13
- **Hash Analysis**: MD5, SHA-1/256/512, Hash identification
- **Password Tools**: Generator with customizable complexity

### 🌐 Web Security Tools
- **SQL Injection**: Payload generation and testing utilities
- **XSS Analysis**: Cross-site scripting payload generators
- **Request Analysis**: HTTP request builder and header analyzer
- **JWT Tools**: JSON Web Token decoder and analyzer

### 🔍 Digital Forensics
- **File Analysis**: Advanced metadata extraction and analysis
- **Steganography**: LSB analysis and hidden data detection
- **Binary Analysis**: Hex viewer and string extraction
- **Network Tools**: PCAP analysis and packet inspection

### ⚙️ Reverse Engineering
- **Disassemblers**: Binary code analysis tools
- **String Extraction**: Extract readable strings from binaries
- **File Format Analysis**: Identify file types and structures

### 🐛 Binary Exploitation
- **ROP Gadgets**: Return-oriented programming tools
- **Shellcode**: Code generation utilities
- **Buffer Overflow**: Pattern generation and offset finding

### 🧩 Miscellaneous Tools
- **QR & Barcode**: Decoder utilities
- **Morse Code**: Text to/from Morse conversion
- **Brainfuck**: Esoteric programming language interpreter

## 🛠️ Installation & Setup

### Quick Start on Replit
1. **Fork this Replit**: Click the "Fork" button
2. **Run the project**: Hit the "Run" button
3. **Open in browser**: Click on the preview URL
4. **Start solving CTFs!** 🎯

### Local Development
```bash
# Clone the repository
git clone https://github.com/0x08006/ctf-arsenal.git
cd ctf-arsenal

# Serve the files (Python 3)
python -m http.server 8000

# Or using Node.js
npx serve .

# Open in browser
open http://localhost:8000
```

## 📖 Usage Examples

### Base64 Encoding/Decoding
```javascript
// Input: "Hello, World!"
// Encoded: SGVsbG8sIFdvcmxkIQ==
// Decoded: Hello, World!
```

### Caesar Cipher Brute Force
```javascript
// Input: "Uryyb, Jbeyq!"
// All 26 possible shifts displayed
// Result: "Hello, World!" (shift 13)
```

### Hash Analysis
```javascript
// Input: "5d41402abc4b2a76b9719d911017c592"
// Analysis: MD5 hash (32 chars, hexadecimal)
// Possible plaintext: "hello"
```

### SQL Injection Payloads
```sql
-- Union-based payload generation
' UNION SELECT user(),database(),version()--
' UNION SELECT table_name,column_name,1 FROM information_schema.columns--
```

## 🏗️ Project Structure

```
ctf-arsenal/
├── index.html          # Main HTML structure
├── style.css           # Styling and animations
├── script.js           # Core functionality and tools
├── README.md           # This file
└── .config/
    └── static-web-server.toml  # Server configuration
```

## 🎨 Technologies Used

- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3
- **Styling**: CSS Grid, Flexbox, CSS Animations
- **Libraries**: 
  - CryptoJS (for cryptographic functions)
  - js-beautify (for code formatting)
  - Font Awesome (for icons)
- **Deployment**: Replit Static Hosting

## 🔧 Key Features Breakdown

### Responsive Modal System
- Dynamic tool loading
- Keyboard shortcuts (ESC to close)
- Mobile-optimized interface

### Advanced Cryptography
- Multiple hash algorithms supported
- Cipher analysis and brute force capabilities
- Rainbow table simulation

### File Analysis
- Binary file inspection
- Metadata extraction
- Entropy calculation for detecting encryption

### Real-time Feedback
- Success/error message system
- Progress indicators
- Input validation

## 🚀 Live Demo

Experience CTF Arsenal live on Replit: [**Launch Demo**](https://replit.com/@username/ctf-arsenal)

## 📱 Screenshots

| Dashboard | Crypto Tools | Web Security |
|-----------|--------------|--------------|
| ![Dashboard](https://via.placeholder.com/250x150/1a1a2e/e94560?text=Dashboard) | ![Crypto](https://via.placeholder.com/250x150/1a1a2e/e94560?text=Crypto+Tools) | ![Web](https://via.placeholder.com/250x150/1a1a2e/e94560?text=Web+Security) |

| Forensics | Reverse Eng | Binary Pwn |
|-----------|-------------|------------|
| ![Forensics](https://via.placeholder.com/250x150/1a1a2e/e94560?text=Forensics) | ![Reverse](https://via.placeholder.com/250x150/1a1a2e/e94560?text=Reverse+Eng) | ![Binary](https://via.placeholder.com/250x150/1a1a2e/e94560?text=Binary+Pwn) |

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-tool`
3. **Add your tool** to the appropriate category
4. **Test thoroughly** across different browsers
5. **Submit a pull request** with a clear description

### Adding New Tools

1. Add tool interface in `getToolInterface()` function
2. Implement tool logic in `script.js`
3. Add tool card to appropriate section in `index.html`
4. Update tool titles mapping in `getToolTitle()`

## 📊 Performance

- **Load Time**: < 2 seconds
- **Tool Response**: < 100ms for most operations
- **Mobile Performance**: Optimized for all devices
- **Browser Support**: Chrome, Firefox, Safari, Edge

## 🔒 Security Notes

- **Client-side only**: All processing happens in the browser
- **No data transmission**: Your data never leaves your device
- **Educational purpose**: Tools are for learning and authorized testing only
- **Responsible disclosure**: Use tools ethically and legally

## 📈 Roadmap

- [ ] **Advanced Steganography**: More image analysis techniques
- [ ] **Blockchain Tools**: Cryptocurrency and smart contract analysis
- [ ] **Machine Learning**: AI-powered pattern recognition
- [ ] **Collaboration**: Real-time team features
- [ ] **Plugin System**: Custom tool development
- [ ] **Offline Mode**: Progressive Web App capabilities

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Font Awesome** for the beautiful icons
- **CryptoJS** for cryptographic functions
- **js-beautify** for code formatting
- **CTF Community** for inspiration and feedback

## 📞 Contact

- **GitHub**: [@0x08006](https://github.com/0x08006)
- **Issues**: [Report bugs or request features](https://github.com/0x08006/ctf-arsenal/issues)

---

<div align="center">

**⭐ Star this repository if you find it useful!**

[🚀 **Try CTF Arsenal Live**](https://replit.com/@username/ctf-arsenal) | [📝 **Report Issues**](https://github.com/0x08006/ctf-arsenal/issues) | [🤝 **Contribute**](https://github.com/0x08006/ctf-arsenal/pulls)

Made with ❤️ for the CTF community

</div>
