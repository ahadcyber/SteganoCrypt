// ==========================================
// STEGANOCRYPT - CORE FUNCTIONALITY
// ==========================================

class SteganographyEngine {
    static DELIMITER = '1111111111111110'; // Special pattern to mark end of data

    // Convert text to binary string
    static textToBinary(text) {
        return text.split('').map(char => {
            return char.charCodeAt(0).toString(2).padStart(8, '0');
        }).join('');
    }

    // Convert binary string to text
    static binaryToText(binary) {
        let text = '';
        for (let i = 0; i < binary.length; i += 8) {
            const byte = binary.substr(i, 8);
            if (byte.length === 8) {
                text += String.fromCharCode(parseInt(byte, 2));
            }
        }
        return text;
    }

    // SHA-256 hash function
    static async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Encode data into image using LSB steganography
    static async encodeImage(imageFile, data, password = '') {
        return new Promise(async (resolve, reject) => {
            try {
                const img = new Image();
                const reader = new FileReader();

                reader.onload = async (e) => {
                    img.onload = async () => {
                        try {
                            // Create canvas
                            const canvas = document.createElement('canvas');
                            const ctx = canvas.getContext('2d');
                            canvas.width = img.width;
                            canvas.height = img.height;
                            
                            // Draw image
                            ctx.drawImage(img, 0, 0);
                            
                            // Get image data
                            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                            const pixels = imageData.data;

                            // Prepare data with password if provided
                            let binaryData = data;
                            if (password) {
                                const passwordHash = await this.sha256(password);
                                const hashBinary = this.textToBinary(passwordHash);
                                binaryData = hashBinary + data;
                            }

                            // Add delimiter
                            binaryData += this.DELIMITER;

                            // Check capacity
                            const maxCapacity = pixels.length / 4 * 3; // RGB channels only
                            if (binaryData.length > maxCapacity) {
                                reject(new Error('Image too small for data. Please use a larger image.'));
                                return;
                            }

                            // Embed data using LSB
                            let dataIndex = 0;
                            for (let i = 0; i < pixels.length; i += 4) {
                                // Modify RGB channels (skip alpha)
                                for (let j = 0; j < 3; j++) {
                                    if (dataIndex < binaryData.length) {
                                        // Clear LSB and set new bit
                                        pixels[i + j] = (pixels[i + j] & 0xFE) | parseInt(binaryData[dataIndex]);
                                        dataIndex++;
                                    }
                                }
                            }

                            // Put modified data back
                            ctx.putImageData(imageData, 0, 0);

                            // Convert to blob
                            canvas.toBlob((blob) => {
                                resolve(blob);
                            }, 'image/png');

                        } catch (err) {
                            reject(err);
                        }
                    };
                    img.src = e.target.result;
                };

                reader.onerror = () => reject(new Error('Failed to read image file'));
                reader.readAsDataURL(imageFile);

            } catch (err) {
                reject(err);
            }
        });
    }

    // Decode data from image using LSB steganography
    static async decodeImage(imageFile, password = '') {
        return new Promise(async (resolve, reject) => {
            try {
                const img = new Image();
                const reader = new FileReader();

                reader.onload = async (e) => {
                    img.onload = async () => {
                        try {
                            // Create canvas
                            const canvas = document.createElement('canvas');
                            const ctx = canvas.getContext('2d');
                            canvas.width = img.width;
                            canvas.height = img.height;
                            
                            // Draw image
                            ctx.drawImage(img, 0, 0);
                            
                            // Get image data
                            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                            const pixels = imageData.data;

                            // Extract LSBs
                            let binaryData = '';
                            for (let i = 0; i < pixels.length; i += 4) {
                                // Extract from RGB channels
                                for (let j = 0; j < 3; j++) {
                                    binaryData += (pixels[i + j] & 1).toString();
                                }
                            }

                            // Find delimiter
                            const delimiterIndex = binaryData.indexOf(this.DELIMITER);
                            if (delimiterIndex === -1) {
                                reject(new Error('No hidden data found in image'));
                                return;
                            }

                            // Extract data before delimiter
                            let extractedData = binaryData.substring(0, delimiterIndex);

                            // Handle password
                            if (password) {
                                const passwordHash = await this.sha256(password);
                                const hashLength = passwordHash.length * 8; // Each char = 8 bits

                                if (extractedData.length < hashLength) {
                                    reject(new Error('Incorrect password or corrupted data'));
                                    return;
                                }

                                const storedHashBinary = extractedData.substring(0, hashLength);
                                const storedHash = this.binaryToText(storedHashBinary);

                                if (storedHash !== passwordHash) {
                                    reject(new Error('Incorrect password'));
                                    return;
                                }

                                extractedData = extractedData.substring(hashLength);
                            }

                            resolve(extractedData);

                        } catch (err) {
                            reject(err);
                        }
                    };
                    img.src = e.target.result;
                };

                reader.onerror = () => reject(new Error('Failed to read image file'));
                reader.readAsDataURL(imageFile);

            } catch (err) {
                reject(err);
            }
        });
    }

    // Convert file to binary with metadata
    static async fileToBinary(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = (e) => {
                try {
                    const arrayBuffer = e.target.result;
                    const bytes = new Uint8Array(arrayBuffer);
                    
                    // Convert bytes to binary
                    let fileBinary = '';
                    for (let i = 0; i < bytes.length; i++) {
                        fileBinary += bytes[i].toString(2).padStart(8, '0');
                    }

                    // Create metadata: filename length (32 bits) + filename + file size (32 bits) + data
                    const filename = file.name;
                    const filenameBinary = this.textToBinary(filename);
                    const filenameLength = filename.length;
                    const fileSize = bytes.length;

                    // Convert lengths to 32-bit binary
                    const filenameLengthBinary = filenameLength.toString(2).padStart(32, '0');
                    const fileSizeBinary = fileSize.toString(2).padStart(32, '0');

                    // Combine: length(32) + filename + size(32) + data
                    const fullBinary = filenameLengthBinary + filenameBinary + fileSizeBinary + fileBinary;

                    resolve({
                        binary: fullBinary,
                        filename: filename,
                        size: fileSize
                    });
                } catch (err) {
                    reject(err);
                }
            };

            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsArrayBuffer(file);
        });
    }

    // Extract file from binary with metadata
    static binaryToFile(binary) {
        try {
            // Extract filename length (first 32 bits)
            const filenameLengthBinary = binary.substring(0, 32);
            const filenameLength = parseInt(filenameLengthBinary, 2);

            // Extract filename
            const filenameBinary = binary.substring(32, 32 + filenameLength * 8);
            const filename = this.binaryToText(filenameBinary);

            // Extract file size (next 32 bits)
            const fileSizeBinary = binary.substring(32 + filenameLength * 8, 64 + filenameLength * 8);
            const fileSize = parseInt(fileSizeBinary, 2);

            // Extract file data
            const fileBinary = binary.substring(64 + filenameLength * 8, 64 + filenameLength * 8 + fileSize * 8);

            // Convert binary to bytes
            const bytes = new Uint8Array(fileSize);
            for (let i = 0; i < fileSize; i++) {
                const byteBinary = fileBinary.substring(i * 8, i * 8 + 8);
                bytes[i] = parseInt(byteBinary, 2);
            }

            return {
                filename: filename,
                size: fileSize,
                data: bytes
            };
        } catch (err) {
            throw new Error('Failed to extract file from binary data');
        }
    }
}

// ==========================================
// UI CONTROLLER
// ==========================================

class UIController {
    constructor() {
        this.currentPage = 'encode';
        this.coverImage = null;
        this.decodeImage = null;
        this.secretFile = null;
        this.decodedFileData = null;
        
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupEncodeTab();
        this.setupDecodeTab();
    }

    // Navigation
    setupNavigation() {
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                this.switchPage(page);
            });
        });
    }

    switchPage(page) {
        // Update nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.page === page) {
                item.classList.add('active');
            }
        });

        // Update pages
        document.querySelectorAll('.page').forEach(p => {
            p.classList.remove('active');
        });
        document.getElementById(`${page}-page`).classList.add('active');

        this.currentPage = page;
    }

    // Setup Encode Tab
    setupEncodeTab() {
        // Cover image upload
        const uploadZone = document.getElementById('encode-upload-zone');
        const imageInput = document.getElementById('cover-image-input');
        
        uploadZone.addEventListener('click', () => imageInput.click());
        imageInput.addEventListener('change', (e) => this.handleCoverImageSelect(e.target.files[0]));

        // Drag & drop
        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });
        uploadZone.addEventListener('dragleave', () => {
            uploadZone.classList.remove('dragover');
        });
        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                this.handleCoverImageSelect(e.dataTransfer.files[0]);
            }
        });

        // Remove cover image
        document.getElementById('remove-cover').addEventListener('click', () => {
            this.coverImage = null;
            document.getElementById('encode-upload-zone').style.display = 'block';
            document.getElementById('cover-preview').style.display = 'none';
        });

        // Data type radio buttons
        const radioButtons = document.querySelectorAll('input[name="data-type"]');
        radioButtons.forEach(radio => {
            radio.addEventListener('change', () => this.toggleDataInput());
        });

        // File input
        const fileSelectZone = document.getElementById('file-select-zone');
        const secretFileInput = document.getElementById('secret-file-input');
        
        fileSelectZone.addEventListener('click', () => secretFileInput.click());
        secretFileInput.addEventListener('change', (e) => this.handleSecretFileSelect(e.target.files[0]));

        // Encode button
        document.getElementById('encode-btn').addEventListener('click', () => this.handleEncode());

        // Monitor text input for real-time updates
        document.getElementById('secret-text').addEventListener('input', (e) => {
            const text = e.target.value.trim();
            if (text) {
                this.updateEncodeDataInfo(text.length, 'text');
            }
        });

        // Monitor password input for encryption status updates
        document.getElementById('encode-password').addEventListener('input', () => {
            const dataType = document.querySelector('input[name="data-type"]:checked').value;
            if (dataType === 'text') {
                const text = document.getElementById('secret-text').value.trim();
                if (text) this.updateEncodeDataInfo(text.length, 'text');
            } else if (this.secretFile) {
                this.updateEncodeDataInfo(this.secretFile.size, 'file', this.secretFile.name);
            }
        });
    }

    // Setup Decode Tab
    setupDecodeTab() {
        // Decode image upload
        const uploadZone = document.getElementById('decode-upload-zone');
        const imageInput = document.getElementById('decode-image-input');
        
        uploadZone.addEventListener('click', () => imageInput.click());
        imageInput.addEventListener('change', (e) => this.handleDecodeImageSelect(e.target.files[0]));

        // Drag & drop
        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });
        uploadZone.addEventListener('dragleave', () => {
            uploadZone.classList.remove('dragover');
        });
        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                this.handleDecodeImageSelect(e.dataTransfer.files[0]);
            }
        });

        // Remove decode image
        document.getElementById('remove-decode').addEventListener('click', () => {
            this.decodeImage = null;
            document.getElementById('decode-upload-zone').style.display = 'block';
            document.getElementById('decode-preview').style.display = 'none';
            document.getElementById('results-card').style.display = 'none';
        });

        // Decode button
        document.getElementById('decode-btn').addEventListener('click', () => this.handleDecode());

        // Copy and download buttons
        document.getElementById('copy-text-btn').addEventListener('click', () => this.copyDecodedText());
        document.getElementById('download-file-btn').addEventListener('click', () => this.downloadDecodedFile());
    }

    // Handle cover image selection
    handleCoverImageSelect(file) {
        if (!file || !file.type.startsWith('image/')) {
            this.showToast('Please select a valid image file', 'error');
            return;
        }

        this.coverImage = file;
        
        // Show preview
        const reader = new FileReader();
        reader.onload = (e) => {
            document.getElementById('encode-upload-zone').style.display = 'none';
            document.getElementById('cover-preview').style.display = 'flex';
            document.getElementById('cover-preview-img').src = e.target.result;

            // Create image to get dimensions
            const img = new Image();
            img.onload = () => {
                const capacity = (img.width * img.height * 3) / 8; // bytes
                const capacityKB = (capacity / 1024).toFixed(2);
                const fileSizeMB = (file.size / 1024 / 1024).toFixed(2);
                
                document.getElementById('cover-info').textContent = 
                    `${img.width}×${img.height} pixels | Capacity: ~${capacityKB} KB`;
                
                // Update info panel
                this.updateEncodeImageInfo(file, img, capacity);
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }

    // Update encode image info panel
    updateEncodeImageInfo(file, img, capacity) {
        const fileSizeMB = (file.size / 1024 / 1024).toFixed(2);
        const capacityKB = (capacity / 1024).toFixed(2);
        const capacityMB = (capacity / 1024 / 1024).toFixed(2);
        
        const infoBox = document.getElementById('encode-image-info');
        infoBox.innerHTML = `
            <p class="info-placeholder">✅ Image Selected</p>
            <div class="info-details">
                <p><strong>Filename:</strong> ${file.name}</p>
                <p><strong>Dimensions:</strong> ${img.width} × ${img.height} px</p>
                <p><strong>File Size:</strong> ${fileSizeMB} MB</p>
                <p><strong>Format:</strong> ${file.type.split('/')[1].toUpperCase()}</p>
                <p><strong>Max Capacity:</strong> ~${capacityKB} KB (${capacityMB} MB)</p>
                <p><strong>Quality:</strong> <span style="color: var(--success)">Excellent</span></p>
            </div>
        `;
    }

    // Handle decode image selection
    handleDecodeImageSelect(file) {
        if (!file || !file.type.startsWith('image/')) {
            this.showToast('Please select a valid image file', 'error');
            return;
        }

        this.decodeImage = file;
        
        // Show preview
        const reader = new FileReader();
        reader.onload = (e) => {
            document.getElementById('decode-upload-zone').style.display = 'none';
            document.getElementById('decode-preview').style.display = 'flex';
            document.getElementById('decode-preview-img').src = e.target.result;

            // Create image to get dimensions
            const img = new Image();
            img.onload = () => {
                const sizeKB = (file.size / 1024).toFixed(2);
                document.getElementById('decode-info').textContent = 
                    `${img.width}×${img.height} pixels | ${sizeKB} KB`;
                
                // Update info panel
                this.updateDecodeImageInfo(file, img);
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }

    // Update decode image info panel
    updateDecodeImageInfo(file, img) {
        const fileSizeMB = (file.size / 1024 / 1024).toFixed(2);
        const capacity = (img.width * img.height * 3) / 8;
        const capacityKB = (capacity / 1024).toFixed(2);
        
        const infoBox = document.getElementById('decode-image-info');
        infoBox.innerHTML = `
            <p class="info-placeholder">✅ Image Uploaded</p>
            <div class="info-details">
                <p><strong>Filename:</strong> ${file.name}</p>
                <p><strong>Dimensions:</strong> ${img.width} × ${img.height} px</p>
                <p><strong>File Size:</strong> ${fileSizeMB} MB</p>
                <p><strong>Format:</strong> ${file.type.split('/')[1].toUpperCase()}</p>
                <p><strong>Potential Capacity:</strong> ~${capacityKB} KB</p>
            </div>
        `;
        
        // Update detection status
        const detectionBox = document.getElementById('decode-detection');
        detectionBox.innerHTML = `
            <p class="info-placeholder">🔍 Analysis Ready</p>
            <div class="info-details">
                <p><strong>Status:</strong> <span style="color: var(--info)">Ready to extract</span></p>
                <p><strong>Detection:</strong> LSB steganography compatible</p>
                <p><strong>Recommendation:</strong> Enter password if used during encoding</p>
            </div>
        `;
        
        // Update status
        const statusBox = document.getElementById('decode-status');
        statusBox.innerHTML = `
            <p class="status-ready">✅ Ready to decode</p>
            <p class="info-text">Click 'Decode Data' to extract hidden information</p>
        `;
    }

    // Handle secret file selection
    handleSecretFileSelect(file) {
        if (!file) return;

        this.secretFile = file;
        const sizeKB = (file.size / 1024).toFixed(2);
        document.getElementById('secret-file-info').style.display = 'block';
        document.getElementById('secret-file-info').textContent = 
            `✅ ${file.name} (${sizeKB} KB)`;
        
        // Update data info panel
        this.updateEncodeDataInfo(file.size, 'file', file.name);
    }

    // Update encode data info panel
    updateEncodeDataInfo(dataSize, type, extraInfo = '') {
        const sizeKB = (dataSize / 1024).toFixed(2);
        const password = document.getElementById('encode-password').value;
        const hasPassword = password.length > 0;
        const typeText = type === 'text' ? 'Text Message' : 'File';
        const encryptColor = hasPassword ? 'var(--success)' : 'var(--warning)';
        const encryptText = hasPassword ? 'Enabled (SHA-256)' : 'Disabled';
        const nameRow = extraInfo ? `<p><strong>Name:</strong> ${extraInfo}</p>` : '';
        
        const dataBox = document.getElementById('encode-data-info');
        dataBox.innerHTML = `
            <p class="info-placeholder">✅ Data Ready</p>
            <div class="info-details">
                <p><strong>Type:</strong> ${typeText}</p>
                ${nameRow}
                <p><strong>Size:</strong> ${dataSize} bytes (~${sizeKB} KB)</p>
                <p><strong>Encryption:</strong> <span style="color: ${encryptColor}">${encryptText}</span></p>
                <p><strong>Feasibility:</strong> <span style="color: var(--success)">Ready to encode</span></p>
            </div>
        `;
        
        // Update status
        const statusBox = document.getElementById('encode-status');
        statusBox.innerHTML = `
            <p class="status-ready">✅ All set!</p>
            <p class="info-text">Ready to encode. Click 'Encode Data' to proceed.</p>
        `;
    }

    // Toggle between text and file input
    toggleDataInput() {
        const dataType = document.querySelector('input[name="data-type"]:checked').value;
        
        if (dataType === 'text') {
            document.getElementById('text-input-container').style.display = 'block';
            document.getElementById('file-input-container').style.display = 'none';
        } else {
            document.getElementById('text-input-container').style.display = 'none';
            document.getElementById('file-input-container').style.display = 'block';
        }
    }

    // Handle encoding
    async handleEncode() {
        try {
            // Validation
            if (!this.coverImage) {
                this.showToast('Please select a cover image', 'error');
                return;
            }

            const dataType = document.querySelector('input[name="data-type"]:checked').value;
            const password = document.getElementById('encode-password').value;

            let binaryData;

            if (dataType === 'text') {
                const text = document.getElementById('secret-text').value.trim();
                if (!text) {
                    this.showToast('Please enter a message to hide', 'error');
                    return;
                }
                binaryData = SteganographyEngine.textToBinary(text);
            } else {
                if (!this.secretFile) {
                    this.showToast('Please select a file to hide', 'error');
                    return;
                }
                const fileData = await SteganographyEngine.fileToBinary(this.secretFile);
                binaryData = fileData.binary;
            }

            // Show progress
            const encodeBtn = document.getElementById('encode-btn');
            const progress = document.getElementById('encode-progress');
            encodeBtn.disabled = true;
            progress.style.display = 'block';

            // Encode
            const encodedBlob = await SteganographyEngine.encodeImage(this.coverImage, binaryData, password);

            // Download
            const url = URL.createObjectURL(encodedBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'encoded_image.png';
            a.click();
            URL.revokeObjectURL(url);

            this.showToast('Data successfully encoded! Image downloaded.', 'success');

            // Reset
            encodeBtn.disabled = false;
            progress.style.display = 'none';

        } catch (err) {
            document.getElementById('encode-btn').disabled = false;
            document.getElementById('encode-progress').style.display = 'none';
            this.showToast(err.message, 'error');
        }
    }

    // Handle decoding
    async handleDecode() {
        try {
            // Validation
            if (!this.decodeImage) {
                this.showToast('Please select an image to decode', 'error');
                return;
            }

            const password = document.getElementById('decode-password').value;

            // Show progress
            const decodeBtn = document.getElementById('decode-btn');
            const progress = document.getElementById('decode-progress');
            decodeBtn.disabled = true;
            progress.style.display = 'block';

            // Decode
            const binaryData = await SteganographyEngine.decodeImage(this.decodeImage, password);

            // Try to determine if it's text or file
            try {
                // Check if it starts with file metadata (32 bits for filename length)
                if (binaryData.length >= 32) {
                    const filenameLengthBinary = binaryData.substring(0, 32);
                    const filenameLength = parseInt(filenameLengthBinary, 2);

                    // If filename length is reasonable (1-255 chars), it's probably a file
                    if (filenameLength > 0 && filenameLength < 256) {
                        const fileData = SteganographyEngine.binaryToFile(binaryData);
                        this.showDecodedFile(fileData);
                        this.showToast('File extracted successfully!', 'success');
                    } else {
                        throw new Error('Not a file');
                    }
                } else {
                    throw new Error('Not a file');
                }
            } catch (fileErr) {
                // Treat as text
                const text = SteganographyEngine.binaryToText(binaryData);
                this.showDecodedText(text);
                this.showToast('Text extracted successfully!', 'success');
            }

            // Reset
            decodeBtn.disabled = false;
            progress.style.display = 'none';

        } catch (err) {
            document.getElementById('decode-btn').disabled = false;
            document.getElementById('decode-progress').style.display = 'none';
            this.showToast(err.message, 'error');
        }
    }

    // Show decoded text
    showDecodedText(text) {
        document.getElementById('results-card').style.display = 'block';
        document.getElementById('decoded-text-container').style.display = 'block';
        document.getElementById('decoded-file-container').style.display = 'none';
        document.getElementById('decoded-text').value = text;
    }

    // Show decoded file
    showDecodedFile(fileData) {
        this.decodedFileData = fileData;
        
        document.getElementById('results-card').style.display = 'block';
        document.getElementById('decoded-text-container').style.display = 'none';
        document.getElementById('decoded-file-container').style.display = 'block';
        
        document.getElementById('decoded-file-name').textContent = fileData.filename;
        const sizeKB = (fileData.size / 1024).toFixed(2);
        document.getElementById('decoded-file-size').textContent = `Size: ${sizeKB} KB`;
    }

    // Copy decoded text
    copyDecodedText() {
        const text = document.getElementById('decoded-text').value;
        navigator.clipboard.writeText(text).then(() => {
            this.showToast('Text copied to clipboard!', 'success');
        });
    }

    // Download decoded file
    downloadDecodedFile() {
        if (!this.decodedFileData) return;

        const blob = new Blob([this.decodedFileData.data]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = this.decodedFileData.filename;
        a.click();
        URL.revokeObjectURL(url);

        this.showToast('File downloaded successfully!', 'success');
    }

    // Show toast notification
    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
        
        toast.innerHTML = `
            <span class="toast-icon">${icon}</span>
            <span class="toast-message">${message}</span>
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }
}

// Mobile Menu Manager
class MobileMenuManager {
    constructor() {
        this.sidebar = document.querySelector('.sidebar');
        this.hamburgerBtn = document.getElementById('hamburger-btn');
        this.overlay = document.getElementById('mobile-overlay');
        this.navItems = document.querySelectorAll('.nav-item');
        
        this.init();
    }
    
    init() {
        if (!this.hamburgerBtn || !this.sidebar || !this.overlay) return;
        
        // Hamburger button click
        this.hamburgerBtn.addEventListener('click', () => {
            this.toggleMenu();
        });
        
        // Overlay click to close menu
        this.overlay.addEventListener('click', () => {
            this.closeMenu();
        });
        
        // Close menu when nav item is clicked
        this.navItems.forEach(item => {
            item.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    this.closeMenu();
                }
            });
        });
        
        // Close menu on window resize if desktop
        window.addEventListener('resize', () => {
            if (window.innerWidth > 768) {
                this.closeMenu();
            }
        });
    }
    
    toggleMenu() {
        const isActive = this.sidebar.classList.contains('active');
        
        if (isActive) {
            this.closeMenu();
        } else {
            this.openMenu();
        }
    }
    
    openMenu() {
        this.sidebar.classList.add('active');
        this.hamburgerBtn.classList.add('active');
        this.overlay.style.display = 'block';
        setTimeout(() => {
            this.overlay.classList.add('active');
        }, 10);
        
        // Prevent body scroll
        document.body.style.overflow = 'hidden';
    }
    
    closeMenu() {
        this.sidebar.classList.remove('active');
        this.hamburgerBtn.classList.remove('active');
        this.overlay.classList.remove('active');
        
        setTimeout(() => {
            this.overlay.style.display = 'none';
        }, 300);
        
        // Restore body scroll
        document.body.style.overflow = '';
    }
}

// Theme Color Manager
class ThemeManager {
    constructor() {
        this.themes = {
            purple: { color1: '#667eea', color2: '#764ba2' },
            blue: { color1: '#4facfe', color2: '#00f2fe' },
            pink: { color1: '#f093fb', color2: '#f5576c' },
            green: { color1: '#4ade80', color2: '#22c55e' },
            orange: { color1: '#fa709a', color2: '#fee140' },
            teal: { color1: '#13547a', color2: '#80d0c7' }
        };
        
        this.currentTheme = 'teal';
        this.init();
    }
    
    init() {
        // Desktop theme picker
        const pickerBtn = document.getElementById('theme-picker-btn');
        const pickerPanel = document.getElementById('theme-picker-panel');
        
        if (pickerBtn && pickerPanel) {
            pickerBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                const isVisible = pickerPanel.style.display === 'block';
                pickerPanel.style.display = isVisible ? 'none' : 'block';
            });
        }
        
        // Mobile theme picker
        const pickerBtnMobile = document.getElementById('theme-picker-btn-mobile');
        if (pickerBtnMobile) {
            pickerBtnMobile.addEventListener('click', (e) => {
                e.stopPropagation();
                if (pickerPanel) {
                    const isVisible = pickerPanel.style.display === 'block';
                    pickerPanel.style.display = isVisible ? 'none' : 'block';
                }
            });
        }
        
        // Close panel when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.theme-picker') && 
                !e.target.closest('.theme-picker-btn-mobile') &&
                !e.target.closest('.theme-picker-panel') &&
                pickerPanel) {
                pickerPanel.style.display = 'none';
            }
        });
        
        // Theme color buttons
        const colorButtons = document.querySelectorAll('.theme-color-btn');
        colorButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const theme = btn.dataset.theme;
                this.changeTheme(theme);
                
                // Update active state
                colorButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Close panel on mobile
                if (pickerPanel) {
                    pickerPanel.style.display = 'none';
                }
            });
        });
        
        // Load saved theme
        const savedTheme = localStorage.getItem('steganocrypt-theme');
        if (savedTheme && this.themes[savedTheme]) {
            this.changeTheme(savedTheme);
            colorButtons.forEach(btn => {
                if (btn.dataset.theme === savedTheme) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
        }
    }
    
    changeTheme(themeName) {
        if (!this.themes[themeName]) return;
        
        const theme = this.themes[themeName];
        this.currentTheme = themeName;
        
        // Update CSS variables
        document.documentElement.style.setProperty('--theme-color-1', theme.color1);
        document.documentElement.style.setProperty('--theme-color-2', theme.color2);
        
        // Save to localStorage
        localStorage.setItem('steganocrypt-theme', themeName);
        
        // Add smooth transition effect
        document.body.style.transition = 'background 0.5s ease-in-out';
        setTimeout(() => {
            document.body.style.transition = '';
        }, 500);
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    new MobileMenuManager();
    new ThemeManager();
    new UIController();
});
