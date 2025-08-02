# 🔍 FileScope

**See Beyond the Surface of Your Files**

FileScope is a powerful, open-source Python tool for in-depth file analysis. Whether you're a cybersecurity enthusiast, developer, or just curious, FileScope helps you uncover what's really inside your files—file types, metadata, entropy, hidden risks, and more—all wrapped in a clean, drag-and-drop GUI with PDF report generation.

---

## ✨ Features

### 🔍 Deep File Analysis
- Detects file types using magic numbers and over **80+ known signatures**.
- Extracts metadata (creation/modification times, size, etc.).
- Calculates MD5, SHA1, and SHA256 checksums.
- Performs **entropy analysis** to flag encryption or obfuscation.
- Validates file headers and structure.
- Extracts embedded objects and metadata (PDF, ZIP, JPEG, MP3, and more).

### 🗂️ Broad Format Support
- **Images**: JPEG, PNG, GIF, BMP  
- **Archives**: ZIP, RAR, 7z, TAR, GZIP  
- **Audio/Video**: MP3, FLAC, Ogg, MP4, WEBM  
- **Documents**: PDF, RTF, XML, JSON  
- **Executables**: EXE, ELF  
- **Fonts**: TTF, OTF  
- ...and many more! *(See `magic_db.py` for the full list.)*

### 🖥️ Interactive GUI
- Built with **Tkinter + TkinterDnD2**.
- Drag-and-drop support for instant file analysis.
- Clean and intuitive interface.
- **One-click PDF report** with visual entropy graphs via ReportLab.

### 🧩 Modular Architecture
- Modular design with separate files for:
  - Magic number detection: `CheckMagic.py`
  - File signature database: `magic_db.py`
- Easily extendable to support new formats or features.

### 🔐 Security-Focused
- Detects spoofed headers and suspicious embedded objects (e.g., JavaScript in PDFs).
- Generates a **risk score** for each file.
- Flags hidden executable-like behavior in non-executables.

---
