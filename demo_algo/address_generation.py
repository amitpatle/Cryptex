#!/usr/bin/env python3
"""
Cryptocurrency Address Generation Algorithms
===========================================

This module demonstrates how to generate cryptocurrency addresses
from public keys for Bitcoin, Ethereum, and Litecoin.
"""

import hashlib
import struct
from typing import Union

class AddressGenerator:
    """Generate cryptocurrency addresses from public keys"""
    
    @staticmethod
    def generate_bitcoin_address(public_key: bytes, testnet: bool = False) -> str:
        """
        Generate Bitcoin address from public key using P2PKH (Pay-to-Public-Key-Hash)
        
        Args:
            public_key: Compressed or uncompressed public key
            testnet: Whether to generate testnet address
            
        Returns:
            str: Bitcoin address
        """
        # Step 1: SHA256 hash of public key
        sha256_hash = hashlib.sha256(public_key).digest()
        
        # Step 2: RIPEMD160 hash of SHA256 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        pubkey_hash = ripemd160.digest()
        
        # Step 3: Add version byte (0x00 for mainnet, 0x6F for testnet)
        version = b'\x6F' if testnet else b'\x00'
        versioned_hash = version + pubkey_hash
        
        # Step 4: Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # Step 5: Combine and encode in base58
        full_address = versioned_hash + checksum
        return AddressGenerator.base58_encode(full_address)
    
    @staticmethod
    def generate_ethereum_address(public_key: bytes) -> str:
        """
        Generate Ethereum address from public key
        
        Args:
            public_key: Uncompressed public key (65 bytes starting with 0x04)
            
        Returns:
            str: Ethereum address (0x + 40 hex characters)
        """
        # Remove the 0x04 prefix if present
        if len(public_key) == 65 and public_key[0] == 0x04:
            public_key = public_key[1:]
        elif len(public_key) != 64:
            raise ValueError("Invalid public key length for Ethereum")
        
        # Keccak256 hash of public key
        keccak_hash = AddressGenerator.keccak256(public_key)
        
        # Take last 20 bytes and add 0x prefix
        address = '0x' + keccak_hash[-20:].hex()
        
        # Apply EIP-55 checksum
        return AddressGenerator.to_checksum_address(address)
    
    @staticmethod
    def generate_litecoin_address(public_key: bytes, testnet: bool = False) -> str:
        """
        Generate Litecoin address from public key
        
        Args:
            public_key: Compressed or uncompressed public key
            testnet: Whether to generate testnet address
            
        Returns:
            str: Litecoin address
        """
        # Step 1: SHA256 hash of public key
        sha256_hash = hashlib.sha256(public_key).digest()
        
        # Step 2: RIPEMD160 hash of SHA256 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        pubkey_hash = ripemd160.digest()
        
        # Step 3: Add version byte (0x30 for mainnet, 0x6F for testnet)
        version = b'\x6F' if testnet else b'\x30'
        versioned_hash = version + pubkey_hash
        
        # Step 4: Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # Step 5: Combine and encode in base58
        full_address = versioned_hash + checksum
        return AddressGenerator.base58_encode(full_address)
    
    @staticmethod
    def generate_segwit_address(public_key: bytes, testnet: bool = False) -> str:
        """
        Generate SegWit (Bech32) address from public key
        
        Args:
            public_key: Compressed public key
            testnet: Whether to generate testnet address
            
        Returns:
            str: SegWit address
        """
        # SHA256 hash of public key
        sha256_hash = hashlib.sha256(public_key).digest()
        
        # RIPEMD160 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        pubkey_hash = ripemd160.digest()
        
        # Convert to 5-bit groups for bech32
        converted = AddressGenerator.convertbits(pubkey_hash, 8, 5)
        
        # Add witness version (0 for P2WPKH)
        spec = [0] + converted
        
        # Encode with bech32
        hrp = 'tb' if testnet else 'bc'
        return AddressGenerator.bech32_encode(hrp, spec)
    
    @staticmethod
    def keccak256(data: bytes) -> bytes:
        """
        Keccak-256 hash function (used by Ethereum)
        Simplified implementation - in production use a proper library
        """
        # This is a simplified version - use hashlib or pycryptodome in production
        import hashlib
        # Note: This uses SHA3-256, not Keccak-256. Use proper library for production.
        return hashlib.sha3_256(data).digest()
    
    @staticmethod
    def to_checksum_address(address: str) -> str:
        """
        Apply EIP-55 checksum to Ethereum address
        
        Args:
            address: Ethereum address (with or without 0x prefix)
            
        Returns:
            str: Checksummed address
        """
        address = address.lower().replace('0x', '')
        hash_bytes = AddressGenerator.keccak256(address.encode('utf-8'))
        hash_hex = hash_bytes.hex()
        
        checksum_address = '0x'
        for i, char in enumerate(address):
            if char.isdigit():
                checksum_address += char
            else:
                # If corresponding hash character is >= 8, capitalize
                if int(hash_hex[i], 16) >= 8:
                    checksum_address += char.upper()
                else:
                    checksum_address += char
        
        return checksum_address
    
    @staticmethod
    def base58_encode(data: bytes) -> str:
        """Encode bytes to base58"""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        num = int.from_bytes(data, 'big')
        encoded = ""
        
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded = alphabet[remainder] + encoded
        
        # Handle leading zeros
        for byte in data:
            if byte == 0:
                encoded = '1' + encoded
            else:
                break
        
        return encoded
    
    @staticmethod
    def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list:
        """Convert between bit groups"""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        
        return ret
    
    @staticmethod
    def bech32_encode(hrp: str, data: list) -> str:
        """Encode data with bech32"""
        combined = data + AddressGenerator.bech32_create_checksum(hrp, data)
        return hrp + '1' + ''.join([AddressGenerator.bech32_charset(d) for d in combined])
    
    @staticmethod
    def bech32_charset(x: int) -> str:
        """Get bech32 character for value"""
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        return charset[x]
    
    @staticmethod
    def bech32_create_checksum(hrp: str, data: list) -> list:
        """Create bech32 checksum"""
        values = AddressGenerator.bech32_hrp_expand(hrp) + data
        polymod = AddressGenerator.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    
    @staticmethod
    def bech32_hrp_expand(hrp: str) -> list:
        """Expand HRP for bech32"""
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    
    @staticmethod
    def bech32_polymod(values: list) -> int:
        """Calculate bech32 polymod"""
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk


def demo_address_generation():
    """Demonstrate address generation algorithms"""
    print("=== Cryptocurrency Address Generation Demo ===\n")
    
    # Sample public keys (compressed and uncompressed)
    compressed_pubkey = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    uncompressed_pubkey = bytes.fromhex("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    
    print("Sample Public Keys:")
    print(f"Compressed:   {compressed_pubkey.hex()}")
    print(f"Uncompressed: {uncompressed_pubkey.hex()}")
    print()
    
    # Bitcoin addresses
    print("1. Bitcoin Addresses:")
    btc_address_compressed = AddressGenerator.generate_bitcoin_address(compressed_pubkey)
    btc_address_uncompressed = AddressGenerator.generate_bitcoin_address(uncompressed_pubkey)
    btc_testnet = AddressGenerator.generate_bitcoin_address(compressed_pubkey, testnet=True)
    
    print(f"   Mainnet (compressed):   {btc_address_compressed}")
    print(f"   Mainnet (uncompressed): {btc_address_uncompressed}")
    print(f"   Testnet:                {btc_testnet}")
    
    # SegWit addresses
    print("\n2. SegWit Addresses:")
    segwit_mainnet = AddressGenerator.generate_segwit_address(compressed_pubkey)
    segwit_testnet = AddressGenerator.generate_segwit_address(compressed_pubkey, testnet=True)
    print(f"   Mainnet: {segwit_mainnet}")
    print(f"   Testnet: {segwit_testnet}")
    
    # Ethereum addresses
    print("\n3. Ethereum Addresses:")
    eth_address = AddressGenerator.generate_ethereum_address(uncompressed_pubkey)
    print(f"   Address: {eth_address}")
    
    # Litecoin addresses
    print("\n4. Litecoin Addresses:")
    ltc_address = AddressGenerator.generate_litecoin_address(compressed_pubkey)
    ltc_testnet = AddressGenerator.generate_litecoin_address(compressed_pubkey, testnet=True)
    print(f"   Mainnet: {ltc_address}")
    print(f"   Testnet: {ltc_testnet}")
    
    # Generate addresses for multiple keys
    print("\n5. Multiple Address Generation:")
    import secrets
    for i in range(3):
        # Generate random public key for demo
        random_key = secrets.token_bytes(33)
        random_key = b'\x02' + random_key[1:]  # Make it compressed format
        
        btc_addr = AddressGenerator.generate_bitcoin_address(random_key)
        ltc_addr = AddressGenerator.generate_litecoin_address(random_key)
        
        print(f"   Set {i+1}:")
        print(f"     Bitcoin:  {btc_addr}")
        print(f"     Litecoin: {ltc_addr}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_address_generation()