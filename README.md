# Steganography Tool - Image Data Hiding

A comprehensive GUI application for hiding and extracting text messages or files inside images using LSB (Least Significant Bit) steganography.

## Features

- 🖼️ **Hide Text Messages**: Embed secret text messages inside images
- 📁 **Hide Files**: Hide any type of file inside images with metadata preservation
- 🔒 **Password Protection**: Optional encryption for sensitive data
- 🎯 **Drag & Drop Interface**: Easy-to-use GUI with drag and drop support
- 📤 **Smart Image Upload**: Upload and analyze images with potential hidden data
- 🔍 **Intelligent Analysis**: Comprehensive steganography detection and analysis
- 📊 **Technical Reports**: Detailed capacity, format, and security analysis
- 🔓 **Data Extraction**: Extract hidden data with automatic type detection
- 📸 **Multiple Formats**: Support for PNG, BMP, JPEG, and GIF images
- 💾 **Lossless Storage**: PNG output format preserves data integrity

## Quick Start

### Option 1: Automatic Setup (Recommended)
1. Run the setup script:
   ```bash
   python setup_and_run.py
   ```
   This will automatically install dependencies and launch the application.

### Option 2: Manual Setup
1. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python steganography_tool.py
   ```

## How to Use

### Hiding Data in Images

1. **Select Cover Image**: 
   - Click "Browse Image" or drag & drop an image file
   - Supported formats: PNG, BMP, JPEG, GIF

2. **Choose Data to Hide**:
   - **Text Message**: Select "Hide Text Message" and enter your secret text
   - **File**: Select "Hide File" and browse for any file to hide

3. **Security (Optional)**:
   - Enter a password for encryption (recommended for sensitive data)
   - Leave empty for no encryption

4. **Save Location**:
   - Choose where to save the modified image
   - PNG format is recommended for best results

5. **Embed Data**:
   - Click "🔒 Embed Data in Image"
   - Wait for the process to complete

### Uploading & Analyzing Images with Hidden Data

1. **Upload Image**:
   - Click "📁 Upload Image" or drag & drop an image file
   - Supports images that may contain hidden data
   - View image preview and basic information

2. **Analyze Image**:
   - Click "🔍 Analyze Image" for comprehensive analysis
   - **Automatic Detection**: Detects hidden data with/without passwords
   - **Technical Analysis**: Shows format, capacity, LSB distribution
   - **Security Assessment**: Identifies steganography indicators
   - **Format Recommendations**: Suggests optimal formats

3. **Extract Hidden Data**:
   - Enter password if the analysis detected password protection
   - Click "🔓 Extract Data from Image"
   - **Smart Detection**: Automatically identifies text vs file data
   - View extracted content in the results area

4. **Save Extracted Results**:
   - **Text Messages**: Save as text file
   - **Hidden Files**: Save with original filename and format
   - **Analysis Report**: Copy technical analysis details

## Technical Details

### How It Works
- Uses LSB (Least Significant Bit) steganography
- Modifies the least significant bits of RGB pixel values
- Invisible changes to the human eye
- Includes data integrity markers and metadata

### Security Features
- SHA-256 hash-based password protection
- Secure data delimiting to prevent false positives
- Metadata preservation for files (filename, size)

### Capacity Guidelines
- Image capacity = Width × Height × 3 bits
- Example: 1920×1080 image can hide ~777KB of data
- Larger images = more data capacity

## Supported Formats

### Input Images
- PNG (recommended)
- JPEG/JPG
- BMP
- GIF

### Output Images
- PNG (recommended for lossless compression)
- BMP

### Hidden Files
- Any file type supported
- Preserves original filename and extension
- Automatic metadata handling

## Best Practices

1. **Use PNG Output**: Always save as PNG to prevent data corruption
2. **Password Protection**: Use strong passwords for sensitive data
3. **Image Quality**: Higher quality images work better
4. **Backup Originals**: Keep original images separate
5. **Size Considerations**: Ensure image is large enough for your data

## Troubleshooting

### Common Issues

**"Image too small for data"**
- Use a larger image or compress your data
- Check the capacity guidelines above

**"No hidden data found"**
- Verify you selected the correct modified image
- Check if a password was used during embedding
- Ensure the image hasn't been compressed or modified

**"Incorrect password"**
- Verify the password used during embedding
- Passwords are case-sensitive

## System Requirements

- Python 3.7 or higher
- Windows, macOS, or Linux
- Required packages (auto-installed):
  - Pillow (PIL)
  - tkinterdnd2

## Analysis Features

### Image Upload & Analysis
The enhanced "Extract Data" tab provides comprehensive analysis:

- **📁 Upload Interface**: Drag & drop or browse for images
- **🔍 Hidden Data Detection**: Automatic detection with/without passwords  
- **📊 Technical Analysis**: Format, dimensions, storage capacity
- **📈 LSB Analysis**: Statistical analysis of least significant bits
- **🔒 Security Assessment**: Password protection detection
- **📋 Detailed Reports**: Complete steganography analysis

### Analysis Report Includes:
- Image format and compatibility assessment
- Maximum storage capacity calculations
- Hidden data detection status
- LSB bit distribution analysis
- Format optimization recommendations
- Security and encryption indicators

## Advanced Usage

### Command Line Interface
The tool is designed as a GUI application, but the core `SteganographyEngine` class can be imported and used programmatically:

```python
from steganography_tool import SteganographyEngine

# Embed text
text_binary = SteganographyEngine.text_to_binary("Secret message")
success = SteganographyEngine.embed_data_in_image(
    "cover.png", text_binary, "output.png", "password"
)

# Extract data
extracted = SteganographyEngine.extract_data_from_image("output.png", "password")
if extracted:
    message = SteganographyEngine.binary_to_text(extracted)
```

## Security Notes

⚠️ **Important Security Considerations**:
- This tool provides basic steganography, not military-grade security
- For highly sensitive data, consider additional encryption
- The modified image should be indistinguishable from the original
- Always use password protection for confidential information
- Test extraction before relying on the hidden data

## License

This project is provided as-is for educational and personal use.

## Contributing

Feel free to suggest improvements or report issues!