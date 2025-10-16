# SteganoCrypt - Web Version

A beautiful, functional steganography web application with ProtonVPN-inspired dark theme UI.

## 🚀 Features

- **Encode Page**: Hide text messages or files inside images
- **Decode Page**: Extract hidden data from encoded images  
- **About Page**: Learn about steganography and technical details
- **ProtonVPN Dark Theme**: Modern purple gradient design with dark background
- **Client-Side Processing**: All operations happen in your browser - 100% private
- **Password Protection**: SHA-256 encryption for secure data hiding
- **Multi-Format Support**: PNG, BMP, JPEG images

## 🎨 Design

The UI is inspired by ProtonVPN's dark theme aesthetic:
- Dark blue-gray background (#1C1C28)
- Purple gradient accents (#6D4AFF to #8B5CF6)
- Modern sidebar navigation
- Card-based layout with smooth animations
- Responsive design

## 🔧 How to Use

### 1. **Open in Browser**
Simply open `index.html` in any modern web browser (Chrome, Firefox, Edge, Safari)

### 2. **Encode Data**
- Select a cover image (drag & drop or click to browse)
- Choose to hide either text or a file
- Optionally add password protection
- Click "Encode Data in Image"
- Encoded image downloads automatically as PNG

### 3. **Decode Data**
- Upload an image containing hidden data
- Enter password if one was used during encoding
- Click "Decode Data from Image"
- View extracted text or download extracted file

## 📁 Files Structure

```
SteganoCrypt/
├── index.html          # Main HTML structure
├── style.css           # ProtonVPN-inspired dark theme
├── script.js           # LSB steganography engine + UI logic
├── steganography_tool.py  # Original Python version
└── WEB_README.md       # This file
```

## 🔐 Technical Details

- **Algorithm**: LSB (Least Significant Bit) Steganography
- **Encryption**: SHA-256 Hash-based Password Protection
- **Image Processing**: HTML5 Canvas API
- **File Handling**: FileReader API & Blob
- **Output Format**: PNG (lossless compression)
- **Capacity**: ~3 bits per pixel (RGB channels)

## 🌐 Browser Compatibility

- ✅ Chrome/Edge (v90+)
- ✅ Firefox (v88+)
- ✅ Safari (v14+)
- ✅ Opera (v76+)

## 💡 Best Practices

1. Use PNG format for best results (lossless)
2. Choose larger images for hiding bigger files
3. Use strong passwords for sensitive data
4. Test extraction before sharing the image
5. Avoid JPEG for critical data (lossy compression)

## 🎯 Differences from Python Version

**Web Version Advantages:**
- No installation required - runs in browser
- Cross-platform (works on any OS with a browser)
- Modern ProtonVPN-inspired UI
- Instant drag & drop functionality
- 100% client-side (no server needed)

**Python Version Advantages:**
- Can process very large images
- More image format optimization options
- Detailed analysis and reporting features
- Command-line interface option

## 🔒 Privacy & Security

- **100% Client-Side Processing**: No data is sent to any server
- **No Tracking**: No analytics or data collection
- **Secure**: Uses Web Crypto API for SHA-256 hashing
- **Open Source**: All code is visible and auditable

## 👨‍💻 Developer

**Abdul Ahad**  
Cybersecurity Expert & Software Engineer

---

**Version**: 1.0 Professional Edition  
**License**: Educational and Personal Use  
**Built with**: Vanilla JavaScript, HTML5, CSS3
