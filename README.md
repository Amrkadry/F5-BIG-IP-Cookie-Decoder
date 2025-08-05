# F5 BIG-IP Cookie Decoder

A simple Python tool to decode and encode F5 BIG-IP persistence cookies.

<img width="724" height="143" alt="image" src="https://github.com/user-attachments/assets/60d25cfc-2c1e-4ae7-8a11-11447e84d1a3" />

## Usage

**Interactive mode:**
```bash
python3 bigip_decoder.py
```

**Decode cookie:**
```bash
python3 bigip_decoder.py 1513228042.47873.0000
```

**Encode IP:port:**
```bash
python3 bigip_decoder.py encode 192.168.1.100:80
```

## What it does

- Decodes BIG-IP cookies to reveal backend server IP and port
- Encodes IP:port combinations into BIG-IP cookie format
- Validates input and handles errors gracefully

## Requirements

- Python 3.x (no external dependencies)
