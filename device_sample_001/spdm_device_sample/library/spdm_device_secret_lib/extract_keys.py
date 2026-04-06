#!/usr/bin/env python3
import subprocess
import binascii
import sys

def extract_priv_key(pem_file):
    """Extract the 48-byte private key scalar from EC P-384 key"""
    result = subprocess.run(['openssl', 'ec', '-in', pem_file, '-outform', 'DER'], 
                           capture_output=True)
    der_key = result.stdout
    
    # EC private key DER structure for P-384:
    # SEQUENCE { version=1, privateKey (OCTET_STRING, 48 bytes), implicit [0] parameters, explicit [1] public key }
    # Look for OCTET_STRING tag (0x04) followed by length 0x30 (48)
    
    for i in range(len(der_key)-50):
        if der_key[i] == 0x04 and der_key[i+1] == 0x30:
            # Found OCTET_STRING of length 48
            return der_key[i+2:i+2+48]
    
    raise ValueError("Could not find 48-byte private key in DER structure")

def extract_pub_key(pem_file):
    """Extract the 96-byte public key (uncompressed point) from EC P-384 cert"""
    result = subprocess.run(['openssl', 'x509', '-in', pem_file, '-pubkey', '-outform', 'DER'],
                           capture_output=True)
    der_cert = result.stdout
    
    # In EC public key, we're looking for BIT STRING with uncompressed point
    # Format: BIT STRING { 0x04 || X (48 bytes) || Y (48 bytes) }
    # The BIT STRING tag is 0x03, followed by length, then 0x00 (unused bits), then 0x04
    
    for i in range(len(der_cert)-100):
        if der_cert[i] == 0x03 and der_cert[i+1] == 0x61:  # BIT STRING, length 97 (1 unused + 1 point type + 96 coords)
            if der_cert[i+3] == 0x04:  # uncompressed point marker
                return der_cert[i+3:i+3+97]  # returns 0x04 + X + Y
    
    raise ValueError("Could not find public key in DER structure")

def format_c_array(data, var_name, line_width=32):
    """Format bytes as C array"""
    print(f"uint8_t {var_name}[] = {{")
    hex_str = binascii.hexlify(data).decode()
    for i in range(0, len(hex_str), line_width):
        line = hex_str[i:i+line_width]
        bytes_line = ", ".join(["0x" + line[j:j+2] for j in range(0, len(line), 2)])
        if i + line_width >= len(hex_str):
            print(f"    {bytes_line}")
        else:
            print(f"    {bytes_line},")
    print("};")

# Generate private key
priv_key = extract_priv_key('smartcard_responder_key.pem')
print("/* Private Key (48 bytes - P-384 scalar) */")
format_c_array(priv_key, "m_libspdm_ec384_responder_private_key", 32)
print()

# Generate public key  
pub_key = extract_pub_key('smartcard_responder.crt')
print("/* Public Key (97 bytes - 0x04 + 48 bytes X + 48 bytes Y for uncompressed point) */")
format_c_array(pub_key, "m_libspdm_ec384_responder_public_key", 32)
print()

# Get root CA cert
result = subprocess.run(['openssl', 'x509', '-in', 'smartcard_root_ca.crt', '-outform', 'DER'],
                       capture_output=True)
root_cert = result.stdout
print(f"/* Root CA Certificate ({len(root_cert)} bytes) */")
format_c_array(root_cert, "m_libspdm_ec384_responder_root_ca", 32)
