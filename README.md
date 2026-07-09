# ScanCrypt Tool

A simple local web tool that analyzes a directory of source files and returns:
- algorithm name
- security level
- implementation type

## Setup

1. Create a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python app.py
   ```
4. Open `http://127.0.0.1:5000` in your browser.

## Usage

Use the folder upload picker to select a directory containing C/C++ source files. The tool will analyze all supported files in the uploaded folder and display the results in a table.

Supported file types: `.c`, `.h`, `.cpp`, `.cc`.

## Notes

- Folder upload uses browser directory selection support (`webkitdirectory`).
- Unsupported file types in the folder are ignored.
