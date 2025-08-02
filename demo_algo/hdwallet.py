#!/usr/bin/env python3
"""
Hierarchical Deterministic (HD) Wallet Implementation
====================================================

This module demonstrates BIP32 HD wallet functionality for generating
deterministic key hierarchies from a single seed.
"""

import hashlib
import hmac
import struct
from typing import Tuple, Optional, List
import secrets

class HDWallet:
    """BIP32 Hierarchical Deterministic Wallet implementation"""
    
    # BIP32 constants
    HARDENED_OFFSET = 0x80000000
    CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    def __init__(self, seed: bytes):
        """
        Initialize HD wallet from seed
        
        Args:
            seed: Master seed (typically 64 bytes from BIP39)
        """
        self.seed = seed
        self.master_private_key, self.master_chain_code = self._generate_master_key()
    
    def _generate_master_key(self) -> Tuple[bytes, bytes]:
        """Generate master private key and chain code from seed"""
        # HMAC-SHA512 with "Bitcoin seed" as key
        hmac_result = hmac.new(b"Bitcoin seed", self.seed, hashlib.sha512).digest()
        
        # Split result: first 32 bytes = private key, last 32 bytes = chain code
        master_private_key = hmac_result[:32]
        master_chain_code = hmac_result[32:]
        
        return master_private_key, master_chain_code
    
    def _derive_child_key(self, parent_key: bytes, parent_chain_code: bytes, 
                         index: int, hardened: bool = False) -> Tuple[bytes, bytes]:
        """
        Derive child key from parent key
        
        Args:
            parent_key: Parent private key (32 bytes)
            parent_chain_code: Parent chain code (32 bytes)
            index: Child index
            hardened: Whether to use hardened derivation
            
        Returns:
            Tuple[bytes, bytes]: (child_private_key, child_chain_code)
        """
        if hardened:
            index += self.HARDENED_OFFSET
            # Hardened derivation: use private key
            data = b'\x00' + parent_key + struct.pack('>I', index)
        else:
            # Non-hardened derivation: use public key
            parent_public_key = self._private_to_public(parent_key)
            data = parent_public_key + struct.pack('>I', index)
        
        # HMAC-SHA512
        hmac_result = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
        
        # Split result
        child_key_part = hmac_result[:32]
        child_chain_code = hmac_result[32:]
        
        # Add parent key to child key part (modulo curve order)
        parent_key_int = int.from_bytes(parent_key, 'big')
        child_key_int = int.from_bytes(child_key_part, 'big')
        
        child_private_key_int = (parent_key_int + child_key_int) % self.CURVE_ORDER
        child_private_key = child_private_key_int.to_bytes(32, 'big')
        
        return child_private_key, child_chain_code
    
    def _private_to_public(self, private_key: bytes) -> bytes:
        """
        Convert private key to compressed public key
        
        Args:
            private_key: 32-byte private key
            
        Returns:
            bytes: 33-byte compressed public key
        """
        # Simplified elliptic curve point multiplication
        # In production, use proper cryptographic library
        
        # secp256k1 generator point
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        
        # Convert private key to integer
        k = int.from_bytes(private_key, 'big')
        
        # Point multiplication (simplified)
        x, y = self._point_multiply(k, Gx, Gy)
        
        # Compressed public key format
        if y % 2 == 0:
            return b'\x02' + x.to_bytes(32, 'big')
        else:
            return b'\x03' + x.to_bytes(32, 'big')
    
    def _point_multiply(self, k: int, x: int, y: int) -> Tuple[int, int]:
        """Simplified elliptic curve point multiplication"""
        # This is a simplified implementation
        # In production, use proper elliptic curve library
        
        if k == 0:
            return 0, 0
        if k == 1:
            return x, y
        
        # Double-and-add algorithm (simplified)
        result_x, result_y = 0, 0
        addend_x, addend_y = x, y
        
        while k:
            if k & 1:
                if result_x == 0:
                    result_x, result_y = addend_x, addend_y
                else:
                    result_x, result_y = self._point_add(result_x, result_y, addend_x, addend_y)
            
            addend_x, addend_y = self._point_double(addend_x, addend_y)
            k >>= 1
        
        return result_x, result_y
    
    def _point_add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Add two points on secp256k1 curve"""
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        
        if x1 == x2:
            if y1 == y2:
                return self._point_double(x1, y1)
            else:
                return 0, 0
        
        s = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
        x3 = (s * s - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        
        return x3, y3
    
    def _point_double(self, x: int, y: int) -> Tuple[int, int]:
        """Double a point on secp256k1 curve"""
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        
        s = ((3 * x * x) * pow(2 * y, -1, p)) % p
        x3 = (s * s - 2 * x) % p
        y3 = (s * (x - x3) - y) % p
        
        return x3, y3
    
    def derive_path(self, path: str) -> Tuple[bytes, bytes]:
        """
        Derive key from BIP32 path
        
        Args:
            path: BIP32 derivation path (e.g., "m/44'/0'/0'/0/0")
            
        Returns:
            Tuple[bytes, bytes]: (private_key, chain_code)
        """
        if not path.startswith('m/'):
            raise ValueError("Path must start with 'm/'")
        
        # Start with master key
        current_key = self.master_private_key
        current_chain_code = self.master_chain_code
        
        # Parse path components
        components = path[2:].split('/')
        
        for component in components:
            if not component:
                continue
            
            # Check for hardened derivation
            if component.endswith("'") or component.endswith('h'):
                index = int(component[:-1])
                hardened = True
            else:
                index = int(component)
                hardened = False
            
            # Derive child key
            current_key, current_chain_code = self._derive_child_key(
                current_key, current_chain_code, index, hardened
            )
        
        return current_key, current_chain_code
    
    def get_address_from_path(self, path: str, address_type: str = 'p2pkh') -> str:
        """
        Get cryptocurrency address from derivation path
        
        Args:
            path: BIP32 derivation path
            address_type: Address type ('p2pkh', 'p2wpkh', 'p2sh')
            
        Returns:
            str: Cryptocurrency address
        """
        private_key, _ = self.derive_path(path)
        public_key = self._private_to_public(private_key)
        
        if address_type == 'p2pkh':
            return self._public_key_to_p2pkh_address(public_key)
        elif address_type == 'p2wpkh':
            return self._public_key_to_p2wpkh_address(public_key)
        else:
            raise ValueError(f"Unsupported address type: {address_type}")
    
    def _public_key_to_p2pkh_address(self, public_key: bytes) -> str:
        """Convert public key to P2PKH address"""
        # Hash160 = RIPEMD160(SHA256(public_key))
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hash160 = ripemd160.digest()
        
        # Add version byte (0x00 for mainnet)
        versioned_hash = b'\x00' + hash160
        
        # Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # Combine and encode in base58
        full_address = versioned_hash + checksum
        return self._base58_encode(full_address)
    
    def _public_key_to_p2wpkh_address(self, public_key: bytes) -> str:
        """Convert public key to P2WPKH (SegWit) address"""
        # This is a simplified implementation
        # In production, use proper bech32 encoding
        
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hash160 = ripemd160.digest()
        
        # Simplified bech32 encoding (for demo)
        return f"bc1q{hash160.hex()}"
    
    def _base58_encode(self, data: bytes) -> str:
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
    
    def generate_account_keys(self, account: int = 0, num_addresses: int = 5) -> dict:
        """
        Generate keys for a BIP44 account
        
        Args:
            account: Account number
            num_addresses: Number of addresses to generate
            
        Returns:
            dict: Account information with addresses
        """
        account_info = {
            'account': account,
            'external_addresses': [],
            'internal_addresses': []
        }
        
        # Generate external addresses (receiving)
        for i in range(num_addresses):
            path = f"m/44'/0'/{account}'/0/{i}"
            private_key, _ = self.derive_path(path)
            address = self.get_address_from_path(path)
            
            account_info['external_addresses'].append({
                'index': i,
                'path': path,
                'address': address,
                'private_key': private_key.hex()
            })
        
        # Generate internal addresses (change)
        for i in range(num_addresses):
            path = f"m/44'/0'/{account}'/1/{i}"
            private_key, _ = self.derive_path(path)
            address = self.get_address_from_path(path)
            
            account_info['internal_addresses'].append({
                'index': i,
                'path': path,
                'address': address,
                'private_key': private_key.hex()
            })
        
        return account_info
    
    def export_extended_key(self, path: str, private: bool = True) -> str:
        """
        Export extended key (xprv/xpub) for given path
        
        Args:
            path: Derivation path
            private: Whether to export private key (xprv) or public key (xpub)
            
        Returns:
            str: Extended key in base58 format
        """
        private_key, chain_code = self.derive_path(path)
        
        if private:
            # Extended private key format
            version = b'\x04\x88\xAD\xE4'  # xprv version
            depth = len(path.split('/')) - 1
            parent_fingerprint = b'\x00\x00\x00\x00'  # Simplified
            child_number = b'\x00\x00\x00\x00'  # Simplified
            key_data = b'\x00' + private_key  # Prefix with 0x00 for private key
        else:
            # Extended public key format
            version = b'\x04\x88\xB2\x1E'  # xpub version
            depth = len(path.split('/')) - 1
            parent_fingerprint = b'\x00\x00\x00\x00'  # Simplified
            child_number = b'\x00\x00\x00\x00'  # Simplified
            key_data = self._private_to_public(private_key)
        
        # Combine all parts
        extended_key = (version + 
                       bytes([depth]) + 
                       parent_fingerprint + 
                       child_number + 
                       chain_code + 
                       key_data)
        
        # Add checksum
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        
        return self._base58_encode(extended_key + checksum)


def demo_hd_wallet():
    """Demonstrate HD wallet functionality"""
    print("=== Hierarchical Deterministic (HD) Wallet Demo ===\n")
    
    # Generate a seed (normally from BIP39 mnemonic)
    seed = secrets.token_bytes(64)  # 512-bit seed
    print(f"Master Seed: {seed.hex()}")
    
    # Create HD wallet
    wallet = HDWallet(seed)
    print(f"Master Private Key: {wallet.master_private_key.hex()}")
    print(f"Master Chain Code: {wallet.master_chain_code.hex()}")
    
    # Demonstrate key derivation paths
    print("\n1. Key Derivation Paths:")
    
    test_paths = [
        "m/0",           # First child
        "m/0'",          # First hardened child
        "m/44'/0'/0'",   # BIP44 account 0
        "m/44'/0'/0'/0/0",  # First receiving address
        "m/44'/0'/0'/1/0",  # First change address
    ]
    
    for path in test_paths:
        private_key, chain_code = wallet.derive_path(path)
        address = wallet.get_address_from_path(path)
        
        print(f"Path: {path}")
        print(f"  Private Key: {private_key.hex()}")
        print(f"  Chain Code:  {chain_code.hex()}")
        print(f"  Address:     {address}")
        print()
    
    # Generate account structure
    print("2. BIP44 Account Structure:")
    account_info = wallet.generate_account_keys(account=0, num_addresses=3)
    
    print(f"Account {account_info['account']}:")
    print("External Addresses (Receiving):")
    for addr_info in account_info['external_addresses']:
        print(f"  {addr_info['index']}: {addr_info['address']} ({addr_info['path']})")
    
    print("Internal Addresses (Change):")
    for addr_info in account_info['internal_addresses']:
        print(f"  {addr_info['index']}: {addr_info['address']} ({addr_info['path']})")
    
    # Multiple accounts
    print("\n3. Multiple Accounts:")
    for account_num in range(3):
        account_path = f"m/44'/0'/{account_num}'"
        private_key, _ = wallet.derive_path(account_path)
        first_address = wallet.get_address_from_path(f"{account_path}/0/0")
        
        print(f"Account {account_num}:")
        print(f"  Account Key: {private_key.hex()[:16]}...")
        print(f"  First Address: {first_address}")
    
    # Extended keys
    print("\n4. Extended Keys:")
    
    account_path = "m/44'/0'/0'"
    xprv = wallet.export_extended_key(account_path, private=True)
    xpub = wallet.export_extended_key(account_path, private=False)
    
    print(f"Account Path: {account_path}")
    print(f"Extended Private Key (xprv): {xprv}")
    print(f"Extended Public Key (xpub):  {xpub}")
    
    # Different address types
    print("\n5. Different Address Types:")
    
    test_path = "m/44'/0'/0'/0/0"
    private_key, _ = wallet.derive_path(test_path)
    
    p2pkh_address = wallet.get_address_from_path(test_path, 'p2pkh')
    p2wpkh_address = wallet.get_address_from_path(test_path, 'p2wpkh')
    
    print(f"Path: {test_path}")
    print(f"P2PKH Address:  {p2pkh_address}")
    print(f"P2WPKH Address: {p2wpkh_address}")
    
    # Demonstrate deterministic nature
    print("\n6. Deterministic Verification:")
    
    # Create another wallet with same seed
    wallet2 = HDWallet(seed)
    
    # Verify same keys are generated
    test_path = "m/44'/0'/0'/0/5"
    key1, _ = wallet.derive_path(test_path)
    key2, _ = wallet2.derive_path(test_path)
    addr1 = wallet.get_address_from_path(test_path)
    addr2 = wallet2.get_address_from_path(test_path)
    
    print(f"Wallet 1 - Path {test_path}:")
    print(f"  Key: {key1.hex()}")
    print(f"  Address: {addr1}")
    
    print(f"Wallet 2 - Path {test_path}:")
    print(f"  Key: {key2.hex()}")
    print(f"  Address: {addr2}")
    
    print(f"Keys match: {key1 == key2}")
    print(f"Addresses match: {addr1 == addr2}")
    
    # BIP44 coin types
    print("\n7. BIP44 Coin Types:")
    
    coin_types = {
        0: "Bitcoin",
        1: "Testnet",
        2: "Litecoin",
        60: "Ethereum",
        144: "Ripple"
    }
    
    for coin_type, coin_name in coin_types.items():
        path = f"m/44'/{coin_type}'/0'/0/0"
        try:
            address = wallet.get_address_from_path(path)
            print(f"{coin_name:10} (m/44'/{coin_type}'): {address}")
        except Exception as e:
            print(f"{coin_name:10} (m/44'/{coin_type}'): Error - {e}")
    
    # Key derivation performance
    print("\n8. Performance Test:")
    import time
    
    start_time = time.time()
    for i in range(100):
        path = f"m/44'/0'/0'/0/{i}"
        wallet.derive_path(path)
    end_time = time.time()
    
    avg_time = (end_time - start_time) / 100
    print(f"Average key derivation time: {avg_time:.6f} seconds")
    print(f"Keys per second: {1/avg_time:.0f}")
    
    # Hardened vs non-hardened derivation
    print("\n9. Hardened vs Non-Hardened Derivation:")
    
    parent_path = "m/44'/0'/0'"
    parent_key, parent_chain = wallet.derive_path(parent_path)
    
    # Non-hardened child
    child_normal_path = parent_path + "/0"
    child_normal_key, _ = wallet.derive_path(child_normal_path)
    
    # Hardened child
    child_hardened_path = parent_path + "/0'"
    child_hardened_key, _ = wallet.derive_path(child_hardened_path)
    
    print(f"Parent Path: {parent_path}")
    print(f"Parent Key: {parent_key.hex()[:16]}...")
    print(f"Normal Child (0): {child_normal_key.hex()[:16]}...")
    print(f"Hardened Child (0'): {child_hardened_key.hex()[:16]}...")
    print("Note: Hardened derivation provides additional security")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_hd_wallet()