#!/usr/bin/env python3
"""
Private and Public Key Generation Algorithms
============================================

This module demonstrates the cryptographic key generation algorithms
used in cryptocurrency wallets for Bitcoin, Ethereum, and other cryptocurrencies.
"""

import hashlib
import secrets
import os
from typing import Tuple

class KeyGenerator:
    """Cryptographic key generation for various cryptocurrencies"""
    
    @staticmethod
    def generate_private_key() -> bytes:
        """
        Generate a cryptographically secure 256-bit private key
        
        Returns:
            bytes: 32-byte private key
        """
        # Use cryptographically secure random number generator
        private_key = secrets.token_bytes(32)
        
        # Ensure the key is within valid range for secp256k1
        # Private key must be between 1 and n-1 where n is the curve order
        secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        key_int = int.from_bytes(private_key, 'big')
        if key_int == 0 or key_int >= secp256k1_order:
            # Recursively generate until we get a valid key
            return KeyGenerator.generate_private_key()
        
        return private_key
    
    @staticmethod
    def private_key_to_wif(private_key: bytes, compressed: bool = True, testnet: bool = False) -> str:
        """
        Convert private key to Wallet Import Format (WIF)
        
        Args:
            private_key: 32-byte private key
            compressed: Whether to use compressed format
            testnet: Whether this is for testnet
            
        Returns:
            str: WIF encoded private key
        """
        # Add version byte (0x80 for mainnet, 0xEF for testnet)
        version = b'\xEF' if testnet else b'\x80'
        extended_key = version + private_key
        
        # Add compression flag if compressed
        if compressed:
            extended_key += b'\x01'
        
        # Calculate checksum (double SHA256)
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        
        # Combine and encode in base58
        full_key = extended_key + checksum
        return KeyGenerator.base58_encode(full_key)
    
    @staticmethod
    def generate_public_key_from_private(private_key: bytes) -> Tuple[bytes, bytes]:
        """
        Generate public key from private key using secp256k1 elliptic curve
        
        Args:
            private_key: 32-byte private key
            
        Returns:
            Tuple[bytes, bytes]: (uncompressed_public_key, compressed_public_key)
        """
        # secp256k1 curve parameters
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a = 0
        b = 7
        gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        
        # Convert private key to integer
        private_int = int.from_bytes(private_key, 'big')
        
        # Point multiplication: public_key = private_key * G
        x, y = KeyGenerator.point_multiply(private_int, gx, gy, p, a)
        
        # Uncompressed public key (0x04 + x + y)
        uncompressed = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        
        # Compressed public key (0x02/0x03 + x)
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        compressed = prefix + x.to_bytes(32, 'big')
        
        return uncompressed, compressed
    
    @staticmethod
    def point_multiply(k: int, x: int, y: int, p: int, a: int) -> Tuple[int, int]:
        """
        Elliptic curve point multiplication using double-and-add algorithm
        
        Args:
            k: Scalar multiplier
            x, y: Point coordinates
            p: Prime modulus
            a: Curve parameter
            
        Returns:
            Tuple[int, int]: Resulting point coordinates
        """
        if k == 0:
            return None, None  # Point at infinity
        
        if k == 1:
            return x, y
        
        # Double-and-add algorithm
        result_x, result_y = None, None
        addend_x, addend_y = x, y
        
        while k:
            if k & 1:  # If bit is set
                if result_x is None:
                    result_x, result_y = addend_x, addend_y
                else:
                    result_x, result_y = KeyGenerator.point_add(
                        result_x, result_y, addend_x, addend_y, p, a
                    )
            
            addend_x, addend_y = KeyGenerator.point_double(addend_x, addend_y, p, a)
            k >>= 1
        
        return result_x, result_y
    
    @staticmethod
    def point_add(x1: int, y1: int, x2: int, y2: int, p: int, a: int) -> Tuple[int, int]:
        """Add two points on elliptic curve"""
        if x1 == x2:
            if y1 == y2:
                return KeyGenerator.point_double(x1, y1, p, a)
            else:
                return None, None  # Point at infinity
        
        # Calculate slope
        s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
        
        # Calculate new point
        x3 = (s * s - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        
        return x3, y3
    
    @staticmethod
    def point_double(x: int, y: int, p: int, a: int) -> Tuple[int, int]:
        """Double a point on elliptic curve"""
        # Calculate slope
        s = ((3 * x * x + a) * pow(2 * y, -1, p)) % p
        
        # Calculate new point
        x3 = (s * s - 2 * x) % p
        y3 = (s * (x - x3) - y) % p
        
        return x3, y3
    
    @staticmethod
    def base58_encode(data: bytes) -> str:
        """Encode bytes to base58"""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        # Convert to integer
        num = int.from_bytes(data, 'big')
        
        # Encode
        encoded = ""
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded = alphabet[remainder] + encoded
        
        # Add leading zeros
        for byte in data:
            if byte == 0:
                encoded = '1' + encoded
            else:
                break
        
        return encoded


def demo_key_generation():
    """Demonstrate key generation algorithms"""
    print("=== Cryptocurrency Key Generation Demo ===\n")
    
    # Generate private key
    print("1. Generating Private Key...")
    private_key = KeyGenerator.generate_private_key()
    print(f"Private Key (hex): {private_key.hex()}")
    print(f"Private Key (int): {int.from_bytes(private_key, 'big')}")
    
    # Convert to WIF
    wif = KeyGenerator.private_key_to_wif(private_key)
    print(f"Private Key (WIF): {wif}")
    
    # Generate public keys
    print("\n2. Generating Public Keys...")
    uncompressed_pub, compressed_pub = KeyGenerator.generate_public_key_from_private(private_key)
    print(f"Uncompressed Public Key: {uncompressed_pub.hex()}")
    print(f"Compressed Public Key: {compressed_pub.hex()}")
    
    # Generate multiple keys
    print("\n3. Generating Multiple Key Pairs...")
    for i in range(3):
        priv = KeyGenerator.generate_private_key()
        _, comp_pub = KeyGenerator.generate_public_key_from_private(priv)
        print(f"Key Pair {i+1}:")
        print(f"  Private: {priv.hex()}")
        print(f"  Public:  {comp_pub.hex()}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_key_generation()