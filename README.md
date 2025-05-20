# Encrypted File Vault

A modern, secure file encryption/decryption tool with a beautiful React-based user interface.

## Features

- File encryption and decryption using AES-256 encryption
- Password protection for files
- Metadata tracking (last opened, locked status)
- Modern React-based user interface with Material-UI
- Secure file handling with proper error checking

## Installation

1. Clone this repository
2. Install backend dependencies:
```bash
pip install -r requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
```

## Running the Application

1. Start the backend server:
```bash
python backend.py
```

2. In a new terminal, start the frontend development server:
```bash
cd frontend
npm run dev
```

3. Open your browser and navigate to `http://localhost:5173`

## Usage

The application provides an intuitive interface with three main functions:

1. **Encrypt Files**
   - Select any file to encrypt
   - Enter a password
   - Download the encrypted file

2. **Decrypt Files**
   - Select an encrypted file
   - Enter the password
   - Download the decrypted file

3. **View Metadata**
   - Select an encrypted file
   - View its metadata (original name, encryption date, last opened, etc.)

## Security Notes

- Files are encrypted using AES-256 encryption
- Passwords are never stored in plain text
- Each file has its own encryption key derived from the password
- Secure password input through masked entry fields 