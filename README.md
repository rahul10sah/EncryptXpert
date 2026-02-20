<p align="center">
  <img src="https://github.com/rahul10sah/EncryptXpert/blob/main/banner.png" alt="EncryptXpert Banner">
</p>

# EncryptXpert: A Universal Multi-Format File Encryption Tool

### An app for file encryption/decryption using AES-EAX or AES-GCM algorithms With GUI & CLI support and Build-in Key Database System For Windows Linux and Mac

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![AES-256](https://img.shields.io/badge/AES-256-Enabled-green)
![PKI](https://img.shields.io/badge/PKI-Enabled-orange)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue)


EncryptXpert is a cutting-edge cybersecurity tool crafted in Python, delivering a comprehensive suite of features for safeguarding sensitive data. With both Graphical User Interface (GUI) and Command-Line Interface (CLI) support, EncryptXpert empowers users to encrypt and decrypt files effortlessly using advanced AES-EAX or AES-GCM algorithms.

This versatile solution ensures robust data protection across Windows and Linux platforms, offering a seamless user experience regardless of the operating system. The intuitive GUI interface simplifies encryption tasks, providing clear options for customizing encryption parameters to suit individual needs.

For users seeking automation or integration into existing workflows, EncryptXpert's CLI tools offer flexibility and efficiency. Whether encrypting single files or entire directories, EncryptXpert streamlines the encryption process while upholding stringent security standards.


## Demo

![Short Demo](https://github.com/rahul10sah/EncryptXpert/blob/main/Demo/encx.gif)

Watch Full Demo 


## Key Features:

- GUI and CLI tools for file encryption and decryption.
- Support for AES-EAX and AES-GCM encryption algorithms.
- Cross-platform compatibility with Windows and Linux environments.
- Intuitive interface for easy customization of encryption parameters.
- Seamless integration into automated workflows for streamlined encryption tasks.

EncryptXpert empowers users to take control of their data security, providing a reliable solution for protecting sensitive information in today's digital landscape. Whether securing personal files or safeguarding corporate assets, EncryptXpert offers a user-friendly and powerful encryption toolkit tailored to meet diverse cybersecurity needs.


## Security Model

EncryptXpert ensures:

- Confidentiality → AES-256 encryption
- Integrity → Authentication tag verification
- Authentication → PKI certificate validation
- Non-repudiation → RSA-PSS digital signatures
- Secure key management → Optional local DB storage


## ❓ Why EncryptXpert?

Unlike simple encryption tools, EncryptXpert integrates:

- Authenticated encryption
- Certificate-based login
- Digital signature verification
- Secure key management

Providing a complete secure file protection ecosystem.

# Pre-Requirements
- Python ( 3.9.0 or Higher )
- PyQT ( v5 or Higher )
- psutil
- pycryptodome

## Installation  

### Software Use ( Windows 10/11 )

Download The EXE File 

### Dev Use ( Linux/ Terminal )

Clone The Repo 
```bash
  git clone https://github.com/rahul10sah/EncryptXpert 
```

Navigate The Repo 

```bash
  cd EncryptXpert
```

Install all Required Packages

```bash
  pip install -r requirements.txt
```
Run The Model

```bash
  Python3 EncryptXpert.py
```
    
## Process 

![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/p12.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/passWD.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/Softwarepic.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/DBpic.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/db2.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/db3.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/ancfile.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/dec1.png)
![App Screenshot](https://github.com/rahul10sah/EncryptXpert/blob/main/images/dec2.png)


## Running Tests

To run tests, run the following command

```bash
  python -m unittest
```

## 🧪 Running Unit Tests

```bash
python -m unittest discover



## ⚠️ Warning: 
Please note that EncryptXpert may encounter occasional issues with the built-in key database system, leading to database failures. Additionally, file integrity may occasionally be compromised during the encryption or decryption process. While efforts are ongoing to address these issues, users are advised to maintain backups of their encrypted files and exercise caution when relying solely on EncryptXpert for data protection.


## FAQ

#### Question 1

Answer 1

#### Question 2

Answer 2


## Contributing

Contributions are always welcome!

See `contributing.md` for ways to get started.



## 🚀 About Me
I'm Self-taught Programmer, Security Researcher ,Technophile And an Open-Source Enthusiast, Maintainer and National level hackathon winner🥇 🇨🇳.



## License

[MIT](https://choosealicense.com/licenses/mit/)

