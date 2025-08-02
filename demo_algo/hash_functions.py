#!/usr/bin/env python3
"""
Cryptographic Hash Functions
===========================

This module demonstrates various cryptographic hash functions used in
cryptocurrency systems, including SHA-256, RIPEMD-160, Keccak-256, and more.
"""

import hashlib
import hmac
from typing import Union, List
import struct

class HashFunctions:
    """Collection of cryptographic hash functions"""
    
    @staticmethod
    def sha256(data: Union[bytes, str]) -> bytes:
        """
        SHA-256 hash function (used extensively in Bitcoin)
        
        Args:
            data: Data to hash
            
        Returns:
            bytes: 32-byte hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def double_sha256(data: Union[bytes, str]) -> bytes:
        """
        Double SHA-256 (SHA-256 of SHA-256) - used in Bitcoin
        
        Args:
            data: Data to hash
            
        Returns:
            bytes: 32-byte hash
        """
        return HashFunctions.sha256(HashFunctions.sha256(data))
    
    @staticmethod
    def ripemd160(data: Union[bytes, str]) -> bytes:
        """
        RIPEMD-160 hash function (used in Bitcoin address generation)
        
        Args:
            data: Data to hash
            
        Returns:
            bytes: 20-byte hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.new('ripemd160', data).digest()
    
    @staticmethod
    def hash160(data: Union[bytes, str]) -> bytes:
        """
        Hash160 = RIPEMD-160(SHA-256(data)) - Bitcoin standard
        
        Args:
            data: Data to hash
            
        Returns:
            bytes: 20-byte hash
        """
        return HashFunctions.ripemd160(HashFunctions.sha256(data))
    
    @staticmethod
    def keccak256(data: Union[bytes, str]) -> bytes:
        """
        Keccak-256 hash function (used in Ethereum)
        Note: This is different from SHA3-256
        
        Args:
            data: Data to hash
            
        Returns:
            bytes: 32-byte hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Note: Using SHA3-256 as approximation
        # In production, use proper Keccak-256 implementation
        return hashlib.sha3_256(data).digest()
    
    @staticmethod
    def sha3_256(data: Union[bytes, str]) -> bytes:
        """
        SHA3-256 hash function
        
        Args:
            data: Data to hash
            
        Returns:
            bytes: 32-byte hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha3_256(data).digest()
    
    @staticmethod
    def blake2b(data: Union[bytes, str], digest_size: int = 32) -> bytes:
        """
        BLAKE2b hash function (used in some cryptocurrencies)
        
        Args:
            data: Data to hash
            digest_size: Output size in bytes
            
        Returns:
            bytes: Hash of specified size
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.blake2b(data, digest_size=digest_size).digest()
    
    @staticmethod
    def scrypt(password: Union[bytes, str], salt: bytes, n: int = 16384, 
               r: int = 8, p: int = 1, dklen: int = 32) -> bytes:
        """
        Scrypt key derivation function (used in Litecoin mining)
        
        Args:
            password: Password/data to hash
            salt: Salt value
            n: CPU/memory cost parameter
            r: Block size parameter
            p: Parallelization parameter
            dklen: Desired key length
            
        Returns:
            bytes: Derived key
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
    
    @staticmethod
    def hmac_sha256(key: Union[bytes, str], message: Union[bytes, str]) -> bytes:
        """
        HMAC-SHA256 (used in various crypto protocols)
        
        Args:
            key: Secret key
            message: Message to authenticate
            
        Returns:
            bytes: 32-byte HMAC
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return hmac.new(key, message, hashlib.sha256).digest()
    
    @staticmethod
    def pbkdf2_sha256(password: Union[bytes, str], salt: bytes, 
                     iterations: int = 100000, dklen: int = 32) -> bytes:
        """
        PBKDF2 with SHA-256 (used for key derivation)
        
        Args:
            password: Password
            salt: Salt value
            iterations: Number of iterations
            dklen: Desired key length
            
        Returns:
            bytes: Derived key
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)
    
    @staticmethod
    def merkle_root(hashes: List[bytes]) -> bytes:
        """
        Calculate Merkle root from list of hashes
        
        Args:
            hashes: List of hash values
            
        Returns:
            bytes: Merkle root hash
        """
        if not hashes:
            return b'\x00' * 32
        
        if len(hashes) == 1:
            return hashes[0]
        
        # Ensure even number of hashes
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])  # Duplicate last hash
        
        # Calculate next level
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            next_level.append(HashFunctions.double_sha256(combined))
        
        return HashFunctions.merkle_root(next_level)
    
    @staticmethod
    def bitcoin_address_checksum(payload: bytes) -> bytes:
        """
        Calculate Bitcoin address checksum
        
        Args:
            payload: Address payload (version + hash160)
            
        Returns:
            bytes: 4-byte checksum
        """
        return HashFunctions.double_sha256(payload)[:4]
    
    @staticmethod
    def ethereum_address_checksum(address: str) -> str:
        """
        Apply EIP-55 checksum to Ethereum address
        
        Args:
            address: Ethereum address (without 0x prefix)
            
        Returns:
            str: Checksummed address
        """
        address = address.lower()
        hash_bytes = HashFunctions.keccak256(address)
        hash_hex = hash_bytes.hex()
        
        result = '0x'
        for i, char in enumerate(address):
            if char.isdigit():
                result += char
            else:
                if int(hash_hex[i], 16) >= 8:
                    result += char.upper()
                else:
                    result += char
        
        return result
    
    @staticmethod
    def proof_of_work_hash(block_header: bytes, nonce: int) -> bytes:
        """
        Calculate proof-of-work hash (simplified Bitcoin mining)
        
        Args:
            block_header: Block header data
            nonce: Nonce value to try
            
        Returns:
            bytes: Hash result
        """
        # Add nonce to block header
        header_with_nonce = block_header + struct.pack('<I', nonce)
        
        # Double SHA-256
        return HashFunctions.double_sha256(header_with_nonce)
    
    @staticmethod
    def check_proof_of_work(hash_result: bytes, difficulty_target: int) -> bool:
        """
        Check if hash meets proof-of-work difficulty target
        
        Args:
            hash_result: Hash to check
            difficulty_target: Target difficulty (number of leading zeros)
            
        Returns:
            bool: True if hash meets target
        """
        # Convert hash to integer (big-endian)
        hash_int = int.from_bytes(hash_result, 'big')
        
        # Check if hash is less than target
        target = 2 ** (256 - difficulty_target)
        return hash_int < target
    
    @staticmethod
    def mine_block(block_header: bytes, difficulty: int, max_nonce: int = 2**32) -> tuple:
        """
        Simple proof-of-work mining simulation
        
        Args:
            block_header: Block header to mine
            difficulty: Number of leading zero bits required
            max_nonce: Maximum nonce to try
            
        Returns:
            tuple: (nonce, hash, success)
        """
        for nonce in range(max_nonce):
            hash_result = HashFunctions.proof_of_work_hash(block_header, nonce)
            
            if HashFunctions.check_proof_of_work(hash_result, difficulty):
                return nonce, hash_result, True
            
            # Progress indicator
            if nonce % 100000 == 0:
                print(f"Tried {nonce:,} nonces...")
        
        return max_nonce, b'', False


def demo_hash_functions():
    """Demonstrate various hash functions"""
    print("=== Cryptographic Hash Functions Demo ===\n")
    
    test_data = "Hello, Bitcoin!"
    test_bytes = test_data.encode('utf-8')
    
    print(f"Test data: '{test_data}'")
    print(f"Test bytes: {test_bytes.hex()}")
    print()
    
    # Basic hash functions
    print("1. Basic Hash Functions:")
    sha256_hash = HashFunctions.sha256(test_data)
    print(f"SHA-256:        {sha256_hash.hex()}")
    
    double_sha256 = HashFunctions.double_sha256(test_data)
    print(f"Double SHA-256: {double_sha256.hex()}")
    
    ripemd160_hash = HashFunctions.ripemd160(test_data)
    print(f"RIPEMD-160:     {ripemd160_hash.hex()}")
    
    hash160 = HashFunctions.hash160(test_data)
    print(f"Hash160:        {hash160.hex()}")
    
    keccak256_hash = HashFunctions.keccak256(test_data)
    print(f"Keccak-256:     {keccak256_hash.hex()}")
    
    sha3_hash = HashFunctions.sha3_256(test_data)
    print(f"SHA3-256:       {sha3_hash.hex()}")
    
    blake2b_hash = HashFunctions.blake2b(test_data)
    print(f"BLAKE2b:        {blake2b_hash.hex()}")
    
    # Key derivation functions
    print("\n2. Key Derivation Functions:")
    salt = b'random_salt_1234567890'
    
    pbkdf2_key = HashFunctions.pbkdf2_sha256(test_data, salt, 10000)
    print(f"PBKDF2-SHA256:  {pbkdf2_key.hex()}")
    
    scrypt_key = HashFunctions.scrypt(test_data, salt, n=1024, r=1, p=1)
    print(f"Scrypt:         {scrypt_key.hex()}")
    
    # HMAC
    print("\n3. HMAC:")
    hmac_key = b'secret_key'
    hmac_result = HashFunctions.hmac_sha256(hmac_key, test_data)
    print(f"HMAC-SHA256:    {hmac_result.hex()}")
    
    # Merkle tree
    print("\n4. Merkle Tree:")
    transaction_hashes = [
        HashFunctions.sha256(f"tx{i}").hex() for i in range(4)
    ]
    print("Transaction hashes:")
    for i, tx_hash in enumerate(transaction_hashes):
        print(f"  TX{i}: {tx_hash}")
    
    # Convert back to bytes for merkle root calculation
    hash_bytes = [bytes.fromhex(h) for h in transaction_hashes]
    merkle_root = HashFunctions.merkle_root(hash_bytes)
    print(f"Merkle Root:    {merkle_root.hex()}")
    
    # Bitcoin address checksum
    print("\n5. Bitcoin Address Checksum:")
    # Example: version byte (0x00) + hash160
    version = b'\x00'
    hash160_example = HashFunctions.hash160("example_public_key")
    payload = version + hash160_example
    checksum = HashFunctions.bitcoin_address_checksum(payload)
    
    print(f"Payload:        {payload.hex()}")
    print(f"Checksum:       {checksum.hex()}")
    print(f"Full Address:   {(payload + checksum).hex()}")
    
    # Ethereum address checksum
    print("\n6. Ethereum Address Checksum:")
    eth_address = "742d35cc6634c0532925a3b8d4c9db96c4b4d8b6"
    checksummed = HashFunctions.ethereum_address_checksum(eth_address)
    print(f"Original:       0x{eth_address}")
    print(f"Checksummed:    {checksummed}")
    
    # Proof of work simulation
    print("\n7. Proof of Work Simulation:")
    block_header = b"Block header data for mining test"
    difficulty = 16  # 16 leading zero bits
    
    print(f"Block header:   {block_header}")
    print(f"Difficulty:     {difficulty} leading zero bits")
    print("Mining... (this may take a moment)")
    
    nonce, hash_result, success = HashFunctions.mine_block(
        block_header, difficulty, max_nonce=1000000
    )
    
    if success:
        print(f"Success! Nonce: {nonce}")
        print(f"Hash:           {hash_result.hex()}")
        print(f"Leading zeros:  {bin(int.from_bytes(hash_result, 'big'))[2:].zfill(256)[:20]}...")
    else:
        print("Mining failed within nonce limit")
    
    # Hash comparison
    print("\n8. Hash Function Comparison:")
    test_inputs = [
        "Bitcoin",
        "Ethereum", 
        "Litecoin",
        "The quick brown fox jumps over the lazy dog"
    ]
    
    for input_str in test_inputs:
        print(f"\nInput: '{input_str}'")
        print(f"  SHA-256:    {HashFunctions.sha256(input_str).hex()[:16]}...")
        print(f"  Keccak-256: {HashFunctions.keccak256(input_str).hex()[:16]}...")
        print(f"  BLAKE2b:    {HashFunctions.blake2b(input_str).hex()[:16]}...")
    
    # Performance comparison (simplified)
    print("\n9. Hash Function Properties:")
    properties = {
        'SHA-256': {'output_size': 32, 'used_in': 'Bitcoin, many others'},
        'RIPEMD-160': {'output_size': 20, 'used_in': 'Bitcoin addresses'},
        'Keccak-256': {'output_size': 32, 'used_in': 'Ethereum'},
        'SHA3-256': {'output_size': 32, 'used_in': 'Various applications'},
        'BLAKE2b': {'output_size': 'variable', 'used_in': 'Zcash, others'},
        'Scrypt': {'output_size': 'variable', 'used_in': 'Litecoin mining'}
    }
    
    for name, props in properties.items():
        print(f"{name:12} - Output: {props['output_size']:>8} bytes, Used in: {props['used_in']}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_hash_functions()