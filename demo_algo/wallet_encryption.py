#!/usr/bin/env python3
"""
Wallet Encryption and Decryption Algorithms
==========================================

This module demonstrates the encryption algorithms used to securely
store wallet data, private keys, and sensitive information.
"""

import hashlib
import secrets
import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import json
import base64

class WalletEncryption:
    """Wallet encryption and decryption utilities"""
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """Generate cryptographically secure salt"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def derive_key_pbkdf2(password: str, salt: bytes, iterations: int = 100000) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: User password
            salt: Random salt
            iterations: Number of iterations
            
        Returns:
            bytes: 32-byte derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def derive_key_scrypt(password: str, salt: bytes, n: int = 16384, r: int = 8, p: int = 1) -> bytes:
        """
        Derive encryption key from password using Scrypt
        
        Args:
            password: User password
            salt: Random salt
            n: CPU/memory cost parameter
            r: Block size parameter
            p: Parallelization parameter
            
        Returns:
            bytes: 32-byte derived key
        """
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            n=n,
            r=r,
            p=p,
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def encrypt_aes_gcm(data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-GCM
        
        Args:
            data: Data to encrypt
            key: 32-byte encryption key
            
        Returns:
            Tuple[bytes, bytes, bytes]: (ciphertext, nonce, tag)
        """
        # Generate random nonce
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return ciphertext, nonce, encryptor.tag
    
    @staticmethod
    def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-GCM
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte encryption key
            nonce: 12-byte nonce
            tag: 16-byte authentication tag
            
        Returns:
            bytes: Decrypted data
        """
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        # Decrypt data
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    @staticmethod
    def encrypt_aes_cbc(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-CBC with PKCS7 padding
        
        Args:
            data: Data to encrypt
            key: 32-byte encryption key
            
        Returns:
            Tuple[bytes, bytes]: (ciphertext, iv)
        """
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Add PKCS7 padding
        padded_data = WalletEncryption.pkcs7_pad(data, 16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return ciphertext, iv
    
    @staticmethod
    def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt data using AES-CBC
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte encryption key
            iv: 16-byte initialization vector
            
        Returns:
            bytes: Decrypted data
        """
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Decrypt data
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        return WalletEncryption.pkcs7_unpad(padded_data)
    
    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int) -> bytes:
        """Add PKCS7 padding"""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def pkcs7_unpad(data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def encrypt_wallet_data(wallet_data: dict, password: str) -> str:
        """
        Encrypt complete wallet data structure
        
        Args:
            wallet_data: Dictionary containing wallet information
            password: User password
            
        Returns:
            str: Base64 encoded encrypted wallet data
        """
        # Convert wallet data to JSON
        json_data = json.dumps(wallet_data, sort_keys=True).encode('utf-8')
        
        # Generate salt
        salt = WalletEncryption.generate_salt()
        
        # Derive key using Scrypt (more secure for password-based encryption)
        key = WalletEncryption.derive_key_scrypt(password, salt)
        
        # Encrypt using AES-GCM
        ciphertext, nonce, tag = WalletEncryption.encrypt_aes_gcm(json_data, key)
        
        # Create encrypted wallet structure
        encrypted_wallet = {
            'version': 1,
            'crypto': {
                'cipher': 'aes-256-gcm',
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8')
            },
            'kdf': {
                'function': 'scrypt',
                'params': {
                    'n': 16384,
                    'r': 8,
                    'p': 1,
                    'salt': base64.b64encode(salt).decode('utf-8')
                }
            }
        }
        
        return base64.b64encode(json.dumps(encrypted_wallet).encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def decrypt_wallet_data(encrypted_data: str, password: str) -> dict:
        """
        Decrypt wallet data structure
        
        Args:
            encrypted_data: Base64 encoded encrypted wallet data
            password: User password
            
        Returns:
            dict: Decrypted wallet data
        """
        # Decode base64 and parse JSON
        encrypted_wallet = json.loads(base64.b64decode(encrypted_data).decode('utf-8'))
        
        # Extract encryption parameters
        salt = base64.b64decode(encrypted_wallet['kdf']['params']['salt'])
        ciphertext = base64.b64decode(encrypted_wallet['crypto']['ciphertext'])
        nonce = base64.b64decode(encrypted_wallet['crypto']['nonce'])
        tag = base64.b64decode(encrypted_wallet['crypto']['tag'])
        
        # Derive key
        if encrypted_wallet['kdf']['function'] == 'scrypt':
            params = encrypted_wallet['kdf']['params']
            key = WalletEncryption.derive_key_scrypt(
                password, salt, params['n'], params['r'], params['p']
            )
        else:
            key = WalletEncryption.derive_key_pbkdf2(password, salt)
        
        # Decrypt data
        decrypted_data = WalletEncryption.decrypt_aes_gcm(ciphertext, key, nonce, tag)
        
        # Parse JSON
        return json.loads(decrypted_data.decode('utf-8'))
    
    @staticmethod
    def create_wallet_backup(wallet_data: dict, password: str) -> str:
        """
        Create encrypted wallet backup
        
        Args:
            wallet_data: Wallet data to backup
            password: Backup password
            
        Returns:
            str: Encrypted backup string
        """
        # Add timestamp and version info
        backup_data = {
            'timestamp': int(time.time()),
            'version': '1.0',
            'wallets': wallet_data
        }
        
        return WalletEncryption.encrypt_wallet_data(backup_data, password)
    
    @staticmethod
    def verify_password(encrypted_data: str, password: str) -> bool:
        """
        Verify if password can decrypt the wallet data
        
        Args:
            encrypted_data: Encrypted wallet data
            password: Password to verify
            
        Returns:
            bool: True if password is correct
        """
        try:
            WalletEncryption.decrypt_wallet_data(encrypted_data, password)
            return True
        except Exception:
            return False


def demo_wallet_encryption():
    """Demonstrate wallet encryption algorithms"""
    print("=== Wallet Encryption Demo ===\n")
    
    # Sample wallet data
    wallet_data = {
        'wallets': [
            {
                'id': '1',
                'name': 'My Bitcoin Wallet',
                'currency': 'BTC',
                'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                'private_key': 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
                'balance': 0.5
            },
            {
                'id': '2',
                'name': 'My Ethereum Wallet',
                'currency': 'ETH',
                'address': '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
                'private_key': '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318',
                'balance': 2.5
            }
        ]
    }
    
    password = "MySecurePassword123!"
    
    print("1. Original Wallet Data:")
    print(json.dumps(wallet_data, indent=2))
    
    # Encrypt wallet data
    print("\n2. Encrypting Wallet Data...")
    encrypted_data = WalletEncryption.encrypt_wallet_data(wallet_data, password)
    print(f"Encrypted Data Length: {len(encrypted_data)} characters")
    print(f"Encrypted Data (first 100 chars): {encrypted_data[:100]}...")
    
    # Verify password
    print("\n3. Password Verification:")
    correct_password = WalletEncryption.verify_password(encrypted_data, password)
    wrong_password = WalletEncryption.verify_password(encrypted_data, "WrongPassword")
    print(f"Correct password verification: {correct_password}")
    print(f"Wrong password verification: {wrong_password}")
    
    # Decrypt wallet data
    print("\n4. Decrypting Wallet Data...")
    try:
        decrypted_data = WalletEncryption.decrypt_wallet_data(encrypted_data, password)
        print("Decryption successful!")
        print("Decrypted data matches original:", decrypted_data == wallet_data)
    except Exception as e:
        print(f"Decryption failed: {e}")
    
    # Demonstrate different encryption methods
    print("\n5. Different Encryption Methods:")
    
    # AES-GCM
    test_data = b"This is sensitive wallet information"
    key = secrets.token_bytes(32)
    
    ciphertext, nonce, tag = WalletEncryption.encrypt_aes_gcm(test_data, key)
    decrypted = WalletEncryption.decrypt_aes_gcm(ciphertext, key, nonce, tag)
    
    print(f"AES-GCM:")
    print(f"  Original: {test_data}")
    print(f"  Encrypted: {ciphertext.hex()}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Match: {test_data == decrypted}")
    
    # AES-CBC
    ciphertext_cbc, iv = WalletEncryption.encrypt_aes_cbc(test_data, key)
    decrypted_cbc = WalletEncryption.decrypt_aes_cbc(ciphertext_cbc, key, iv)
    
    print(f"\nAES-CBC:")
    print(f"  Original: {test_data}")
    print(f"  Encrypted: {ciphertext_cbc.hex()}")
    print(f"  Decrypted: {decrypted_cbc}")
    print(f"  Match: {test_data == decrypted_cbc}")
    
    # Key derivation comparison
    print("\n6. Key Derivation Comparison:")
    password_test = "TestPassword123"
    salt = WalletEncryption.generate_salt()
    
    import time
    
    # PBKDF2
    start_time = time.time()
    pbkdf2_key = WalletEncryption.derive_key_pbkdf2(password_test, salt)
    pbkdf2_time = time.time() - start_time
    
    # Scrypt
    start_time = time.time()
    scrypt_key = WalletEncryption.derive_key_scrypt(password_test, salt)
    scrypt_time = time.time() - start_time
    
    print(f"PBKDF2 Key: {pbkdf2_key.hex()}")
    print(f"PBKDF2 Time: {pbkdf2_time:.4f} seconds")
    print(f"Scrypt Key: {scrypt_key.hex()}")
    print(f"Scrypt Time: {scrypt_time:.4f} seconds")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    import time
    demo_wallet_encryption()