#!/usr/bin/env python3
import struct
import socket

def decode_bigip_cookie(cookie_value):
    """
    Decode F5 BIG-IP persistence cookie value.
    Format: <ip_encoded>.<port_encoded>.<optional_flags>
    
    The IP is encoded as a 32-bit integer in network byte order.
    The port is encoded as a 16-bit integer, but stored as decimal.
    """
    try:
        parts = cookie_value.strip().split('.')
        if len(parts) < 2:
            return "Invalid cookie format. Expected at least two parts separated by dots."
        
        ip_encoded = int(parts[0])
        port_encoded = int(parts[1])
        
        # Decode IP address from 32-bit integer
        # BIG-IP actually stores IP in little-endian format for the cookie
        ip_bytes = struct.pack('<I', ip_encoded)  # Convert to little-endian bytes
        ip = socket.inet_ntoa(ip_bytes)
        
        # Decode port from encoded format (16-bit integer in network byte order)
        port = struct.unpack('>H', struct.pack('>H', port_encoded & 0xFFFF))[0]
        
        # For BIG-IP, port is often encoded with byte swapping
        port = ((port_encoded & 0xFF) << 8) | ((port_encoded & 0xFF00) >> 8)
        
        if port < 1 or port > 65535:
            return f"Invalid decoded port number: {port}. Original encoded: {port_encoded}"
        
        result = f"Decoded internal server: {ip}:{port}"
        result += f"\nOriginal encoded values: IP={ip_encoded}, Port={port_encoded}"
        
        # If there are additional parts, show them as flags
        if len(parts) > 2:
            flags = '.'.join(parts[2:])
            result += f"\nAdditional flags: {flags}"
        
        return result
        
    except ValueError as e:
        return f"Invalid input: Make sure the IP and port values are numeric. Error: {e}"
    except struct.error as e:
        return f"Error decoding IP address: {e}"
    except socket.error as e:
        return f"Error converting IP address: {e}"
    except Exception as e:
        return f"Unexpected error decoding cookie: {e}"

def encode_bigip_cookie(ip, port):
    """
    Encode an IP and port into BIG-IP cookie format.
    Useful for testing or understanding the encoding process.
    """
    try:
        # Convert IP to 32-bit integer in little-endian format
        ip_bytes = socket.inet_aton(ip)
        ip_encoded = struct.unpack('<I', ip_bytes)[0]
        
        # Validate port
        port = int(port)
        if port < 1 or port > 65535:
            return f"Invalid port number: {port}. Must be between 1-65535."
        
        # Encode port with byte swapping (same as BIG-IP does)
        port_encoded = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8)
        
        return f"{ip_encoded}.{port_encoded}.0000"
        
    except socket.error:
        return f"Invalid IP address format: {ip}"
    except ValueError:
        return f"Invalid port number: {port}"
    except Exception as e:
        return f"Error encoding: {e}"

def main():
    """Main function with interactive menu"""
    print("F5 BIG-IP Cookie Decoder/Encoder")
    print("=" * 35)
    
    while True:
        print("\nOptions:")
        print("1. Decode BIG-IP cookie")
        print("2. Encode IP:Port to BIG-IP cookie")
        print("3. Quit")
        
        choice = input("\nSelect an option (1-3): ").strip()
        
        if choice == '1':
            cookie_value = input("Enter BIG-IP cookie value (e.g. 1513228042.47873.0000): ")
            result = decode_bigip_cookie(cookie_value)
            print(f"\nResult: {result}")
            
        elif choice == '2':
            ip = input("Enter IP address (e.g. 192.168.1.100): ")
            port = input("Enter port number (e.g. 80): ")
            result = encode_bigip_cookie(ip, port)
            print(f"\nEncoded cookie: {result}")
            
        elif choice == '3':
            print("Goodbye!")
            break
            
        else:
            print("Invalid option. Please select 1, 2, or 3.")

# Command line usage
if __name__ == "__main__":
    import sys
    
    # If arguments provided, use command line mode
    if len(sys.argv) == 2:
        result = decode_bigip_cookie(sys.argv[1])
        print(result)
    elif len(sys.argv) == 3 and sys.argv[1] == "encode":
        ip_port = sys.argv[2].split(':')
        if len(ip_port) == 2:
            result = encode_bigip_cookie(ip_port[0], ip_port[1])
            print(result)
        else:
            print("Usage for encoding: python3 bigip_decoder.py encode <ip:port>")
    else:
        # Interactive mode
        main()
