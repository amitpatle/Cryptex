#!/usr/bin/env python3
"""
Transaction Signing Algorithms
=============================

This module demonstrates digital signature algorithms used for
signing cryptocurrency transactions, including ECDSA and EdDSA.
"""

import hashlib
import secrets
from typing import Tuple, Optional
import struct
import json

class TransactionSigner:
    """Digital signature algorithms for cryptocurrency transactions"""
    
    # secp256k1 curve parameters
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    
    @staticmethod
    def sign_ecdsa(message_hash: bytes, private_key: bytes) -> Tuple[int, int]:
        """
        Sign message hash using ECDSA (Elliptic Curve Digital Signature Algorithm)
        
        Args:
            message_hash: 32-byte hash of message to sign
            private_key: 32-byte private key
            
        Returns:
            Tuple[int, int]: (r, s) signature components
        """
        # Convert private key to integer
        d = int.from_bytes(private_key, 'big')
        
        # Convert message hash to integer
        z = int.from_bytes(message_hash, 'big')
        
        while True:
            # Generate random nonce k
            k = secrets.randbelow(TransactionSigner.N - 1) + 1
            
            # Calculate r = (k * G).x mod n
            kG = TransactionSigner.point_multiply(k, TransactionSigner.G[0], TransactionSigner.G[1])
            r = kG[0] % TransactionSigner.N
            
            if r == 0:
                continue
            
            # Calculate s = k^(-1) * (z + r * d) mod n
            k_inv = TransactionSigner.mod_inverse(k, TransactionSigner.N)
            s = (k_inv * (z + r * d)) % TransactionSigner.N
            
            if s == 0:
                continue
            
            # Use low-s value (BIP 62)
            if s > TransactionSigner.N // 2:
                s = TransactionSigner.N - s
            
            return r, s
    
    @staticmethod
    def verify_ecdsa(message_hash: bytes, signature: Tuple[int, int], public_key: Tuple[int, int]) -> bool:
        """
        Verify ECDSA signature
        
        Args:
            message_hash: 32-byte hash of signed message
            signature: (r, s) signature components
            public_key: (x, y) public key coordinates
            
        Returns:
            bool: True if signature is valid
        """
        r, s = signature
        
        # Check signature components are in valid range
        if not (1 <= r < TransactionSigner.N and 1 <= s < TransactionSigner.N):
            return False
        
        # Convert message hash to integer
        z = int.from_bytes(message_hash, 'big')
        
        # Calculate signature verification
        s_inv = TransactionSigner.mod_inverse(s, TransactionSigner.N)
        u1 = (z * s_inv) % TransactionSigner.N
        u2 = (r * s_inv) % TransactionSigner.N
        
        # Calculate point: u1*G + u2*Q
        point1 = TransactionSigner.point_multiply(u1, TransactionSigner.G[0], TransactionSigner.G[1])
        point2 = TransactionSigner.point_multiply(u2, public_key[0], public_key[1])
        result_point = TransactionSigner.point_add(point1[0], point1[1], point2[0], point2[1])
        
        # Verify r component
        return result_point[0] % TransactionSigner.N == r
    
    @staticmethod
    def sign_bitcoin_transaction(tx_data: dict, private_key: bytes, input_index: int) -> bytes:
        """
        Sign Bitcoin transaction using SIGHASH_ALL
        
        Args:
            tx_data: Transaction data dictionary
            private_key: Private key for signing
            input_index: Index of input being signed
            
        Returns:
            bytes: DER encoded signature with SIGHASH_ALL flag
        """
        # Create transaction hash for signing
        tx_hash = TransactionSigner.create_bitcoin_tx_hash(tx_data, input_index)
        
        # Sign the hash
        r, s = TransactionSigner.sign_ecdsa(tx_hash, private_key)
        
        # Encode signature in DER format
        der_sig = TransactionSigner.encode_der_signature(r, s)
        
        # Add SIGHASH_ALL flag (0x01)
        return der_sig + b'\x01'
    
    @staticmethod
    def sign_ethereum_transaction(tx_data: dict, private_key: bytes, chain_id: int = 1) -> dict:
        """
        Sign Ethereum transaction (EIP-155)
        
        Args:
            tx_data: Transaction data dictionary
            private_key: Private key for signing
            chain_id: Ethereum chain ID
            
        Returns:
            dict: Signed transaction with v, r, s values
        """
        # Create RLP encoded transaction for signing
        rlp_data = TransactionSigner.create_ethereum_tx_rlp(tx_data, chain_id)
        
        # Hash the RLP data
        tx_hash = TransactionSigner.keccak256(rlp_data)
        
        # Sign the hash
        r, s = TransactionSigner.sign_ecdsa(tx_hash, private_key)
        
        # Calculate recovery ID (v)
        # For EIP-155: v = recovery_id + 2 * chain_id + 35
        recovery_id = TransactionSigner.calculate_recovery_id(tx_hash, (r, s), private_key)
        v = recovery_id + 2 * chain_id + 35
        
        # Add signature to transaction
        signed_tx = tx_data.copy()
        signed_tx.update({
            'v': v,
            'r': r,
            's': s
        })
        
        return signed_tx
    
    @staticmethod
    def create_bitcoin_tx_hash(tx_data: dict, input_index: int) -> bytes:
        """Create Bitcoin transaction hash for signing"""
        # Simplified transaction serialization for demo
        # In production, use proper Bitcoin transaction serialization
        
        tx_copy = tx_data.copy()
        
        # Clear all input scripts except the one being signed
        for i, inp in enumerate(tx_copy['inputs']):
            if i == input_index:
                # Use the previous output's script
                inp['script'] = inp['prev_script']
            else:
                inp['script'] = b''
        
        # Serialize transaction
        serialized = TransactionSigner.serialize_bitcoin_tx(tx_copy)
        
        # Add SIGHASH_ALL flag
        serialized += struct.pack('<I', 1)  # SIGHASH_ALL
        
        # Double SHA256
        return hashlib.sha256(hashlib.sha256(serialized).digest()).digest()
    
    @staticmethod
    def create_ethereum_tx_rlp(tx_data: dict, chain_id: int) -> bytes:
        """Create RLP encoded Ethereum transaction for signing"""
        # Simplified RLP encoding for demo
        # In production, use proper RLP library
        
        fields = [
            tx_data.get('nonce', 0),
            tx_data.get('gas_price', 0),
            tx_data.get('gas_limit', 21000),
            bytes.fromhex(tx_data.get('to', '').replace('0x', '')),
            tx_data.get('value', 0),
            bytes.fromhex(tx_data.get('data', '').replace('0x', '')),
            chain_id,
            0,  # r placeholder
            0   # s placeholder
        ]
        
        return TransactionSigner.rlp_encode(fields)
    
    @staticmethod
    def serialize_bitcoin_tx(tx_data: dict) -> bytes:
        """Serialize Bitcoin transaction (simplified)"""
        result = b''
        
        # Version
        result += struct.pack('<I', tx_data.get('version', 1))
        
        # Input count
        result += TransactionSigner.encode_varint(len(tx_data['inputs']))
        
        # Inputs
        for inp in tx_data['inputs']:
            result += bytes.fromhex(inp['prev_hash'])[::-1]  # Reverse for little-endian
            result += struct.pack('<I', inp['prev_index'])
            script = inp['script']
            result += TransactionSigner.encode_varint(len(script))
            result += script
            result += struct.pack('<I', inp.get('sequence', 0xffffffff))
        
        # Output count
        result += TransactionSigner.encode_varint(len(tx_data['outputs']))
        
        # Outputs
        for out in tx_data['outputs']:
            result += struct.pack('<Q', out['value'])
            script = out['script']
            result += TransactionSigner.encode_varint(len(script))
            result += script
        
        # Locktime
        result += struct.pack('<I', tx_data.get('locktime', 0))
        
        return result
    
    @staticmethod
    def encode_varint(value: int) -> bytes:
        """Encode variable length integer"""
        if value < 0xfd:
            return struct.pack('<B', value)
        elif value <= 0xffff:
            return b'\xfd' + struct.pack('<H', value)
        elif value <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', value)
        else:
            return b'\xff' + struct.pack('<Q', value)
    
    @staticmethod
    def rlp_encode(data) -> bytes:
        """Simple RLP encoding (for demo purposes)"""
        # This is a simplified version - use proper RLP library in production
        if isinstance(data, int):
            if data == 0:
                return b'\x80'
            return data.to_bytes((data.bit_length() + 7) // 8, 'big')
        elif isinstance(data, bytes):
            if len(data) == 1 and data[0] < 0x80:
                return data
            elif len(data) < 56:
                return bytes([0x80 + len(data)]) + data
            else:
                length_bytes = len(data).to_bytes((len(data).bit_length() + 7) // 8, 'big')
                return bytes([0xb7 + len(length_bytes)]) + length_bytes + data
        elif isinstance(data, list):
            encoded_items = b''.join(TransactionSigner.rlp_encode(item) for item in data)
            if len(encoded_items) < 56:
                return bytes([0xc0 + len(encoded_items)]) + encoded_items
            else:
                length_bytes = len(encoded_items).to_bytes((len(encoded_items).bit_length() + 7) // 8, 'big')
                return bytes([0xf7 + len(length_bytes)]) + length_bytes + encoded_items
    
    @staticmethod
    def encode_der_signature(r: int, s: int) -> bytes:
        """Encode signature in DER format"""
        def encode_der_integer(value: int) -> bytes:
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            if value_bytes[0] & 0x80:
                value_bytes = b'\x00' + value_bytes
            return b'\x02' + bytes([len(value_bytes)]) + value_bytes
        
        r_der = encode_der_integer(r)
        s_der = encode_der_integer(s)
        
        sequence = r_der + s_der
        return b'\x30' + bytes([len(sequence)]) + sequence
    
    @staticmethod
    def calculate_recovery_id(message_hash: bytes, signature: Tuple[int, int], private_key: bytes) -> int:
        """Calculate ECDSA recovery ID"""
        r, s = signature
        
        # Generate public key from private key
        d = int.from_bytes(private_key, 'big')
        public_key = TransactionSigner.point_multiply(d, TransactionSigner.G[0], TransactionSigner.G[1])
        
        # Try different recovery IDs
        for recovery_id in range(4):
            recovered_key = TransactionSigner.recover_public_key(message_hash, signature, recovery_id)
            if recovered_key and recovered_key == public_key:
                return recovery_id
        
        return 0
    
    @staticmethod
    def recover_public_key(message_hash: bytes, signature: Tuple[int, int], recovery_id: int) -> Optional[Tuple[int, int]]:
        """Recover public key from signature"""
        r, s = signature
        
        # Calculate point R
        x = r + (recovery_id // 2) * TransactionSigner.N
        if x >= TransactionSigner.P:
            return None
        
        # Calculate y coordinate
        y_squared = (pow(x, 3, TransactionSigner.P) + 7) % TransactionSigner.P
        y = pow(y_squared, (TransactionSigner.P + 1) // 4, TransactionSigner.P)
        
        if y % 2 != recovery_id % 2:
            y = TransactionSigner.P - y
        
        R = (x, y)
        
        # Calculate public key
        z = int.from_bytes(message_hash, 'big')
        r_inv = TransactionSigner.mod_inverse(r, TransactionSigner.N)
        
        point1 = TransactionSigner.point_multiply(s, R[0], R[1])
        point2 = TransactionSigner.point_multiply(z, TransactionSigner.G[0], TransactionSigner.G[1])
        point2 = (point2[0], (-point2[1]) % TransactionSigner.P)  # Negate point
        
        result = TransactionSigner.point_add(point1[0], point1[1], point2[0], point2[1])
        return TransactionSigner.point_multiply(r_inv, result[0], result[1])
    
    @staticmethod
    def keccak256(data: bytes) -> bytes:
        """Keccak-256 hash (simplified - use proper library in production)"""
        return hashlib.sha3_256(data).digest()
    
    # Elliptic curve math functions (same as in key_generation.py)
    @staticmethod
    def point_multiply(k: int, x: int, y: int) -> Tuple[int, int]:
        """Elliptic curve point multiplication"""
        if k == 0:
            return None, None
        if k == 1:
            return x, y
        
        result_x, result_y = None, None
        addend_x, addend_y = x, y
        
        while k:
            if k & 1:
                if result_x is None:
                    result_x, result_y = addend_x, addend_y
                else:
                    result_x, result_y = TransactionSigner.point_add(
                        result_x, result_y, addend_x, addend_y
                    )
            
            addend_x, addend_y = TransactionSigner.point_double(addend_x, addend_y)
            k >>= 1
        
        return result_x, result_y
    
    @staticmethod
    def point_add(x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        """Add two points on elliptic curve"""
        if x1 == x2:
            if y1 == y2:
                return TransactionSigner.point_double(x1, y1)
            else:
                return None, None
        
        s = ((y2 - y1) * TransactionSigner.mod_inverse(x2 - x1, TransactionSigner.P)) % TransactionSigner.P
        x3 = (s * s - x1 - x2) % TransactionSigner.P
        y3 = (s * (x1 - x3) - y1) % TransactionSigner.P
        
        return x3, y3
    
    @staticmethod
    def point_double(x: int, y: int) -> Tuple[int, int]:
        """Double a point on elliptic curve"""
        s = ((3 * x * x) * TransactionSigner.mod_inverse(2 * y, TransactionSigner.P)) % TransactionSigner.P
        x3 = (s * s - 2 * x) % TransactionSigner.P
        y3 = (s * (x - x3) - y) % TransactionSigner.P
        
        return x3, y3
    
    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """Calculate modular inverse using extended Euclidean algorithm"""
        if a < 0:
            a = (a % m + m) % m
        
        g, x, _ = TransactionSigner.extended_gcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        
        return x % m
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean algorithm"""
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = TransactionSigner.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y


def demo_transaction_signing():
    """Demonstrate transaction signing algorithms"""
    print("=== Transaction Signing Demo ===\n")
    
    # Generate test keys
    private_key = secrets.token_bytes(32)
    d = int.from_bytes(private_key, 'big')
    public_key = TransactionSigner.point_multiply(d, TransactionSigner.G[0], TransactionSigner.G[1])
    
    print("1. Test Keys:")
    print(f"Private Key: {private_key.hex()}")
    print(f"Public Key: ({hex(public_key[0])}, {hex(public_key[1])})")
    
    # Test ECDSA signing and verification
    print("\n2. ECDSA Signature Test:")
    message = b"Hello, Bitcoin!"
    message_hash = hashlib.sha256(message).digest()
    
    print(f"Message: {message}")
    print(f"Message Hash: {message_hash.hex()}")
    
    # Sign message
    r, s = TransactionSigner.sign_ecdsa(message_hash, private_key)
    print(f"Signature: r={hex(r)}, s={hex(s)}")
    
    # Verify signature
    is_valid = TransactionSigner.verify_ecdsa(message_hash, (r, s), public_key)
    print(f"Signature Valid: {is_valid}")
    
    # Test with wrong message
    wrong_hash = hashlib.sha256(b"Wrong message").digest()
    is_invalid = TransactionSigner.verify_ecdsa(wrong_hash, (r, s), public_key)
    print(f"Wrong Message Valid: {is_invalid}")
    
    # Bitcoin transaction signing
    print("\n3. Bitcoin Transaction Signing:")
    bitcoin_tx = {
        'version': 1,
        'inputs': [{
            'prev_hash': 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890',
            'prev_index': 0,
            'prev_script': b'\x76\xa9\x14' + secrets.token_bytes(20) + b'\x88\xac',  # P2PKH script
            'sequence': 0xffffffff
        }],
        'outputs': [{
            'value': 5000000000,  # 50 BTC in satoshis
            'script': b'\x76\xa9\x14' + secrets.token_bytes(20) + b'\x88\xac'
        }],
        'locktime': 0
    }
    
    btc_signature = TransactionSigner.sign_bitcoin_transaction(bitcoin_tx, private_key, 0)
    print(f"Bitcoin Signature: {btc_signature.hex()}")
    
    # Ethereum transaction signing
    print("\n4. Ethereum Transaction Signing:")
    ethereum_tx = {
        'nonce': 42,
        'gas_price': 20000000000,  # 20 Gwei
        'gas_limit': 21000,
        'to': '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
        'value': 1000000000000000000,  # 1 ETH in wei
        'data': ''
    }
    
    signed_eth_tx = TransactionSigner.sign_ethereum_transaction(ethereum_tx, private_key, chain_id=1)
    print(f"Signed Ethereum Transaction:")
    print(f"  v: {signed_eth_tx['v']}")
    print(f"  r: {hex(signed_eth_tx['r'])}")
    print(f"  s: {hex(signed_eth_tx['s'])}")
    
    # DER encoding test
    print("\n5. DER Signature Encoding:")
    der_encoded = TransactionSigner.encode_der_signature(r, s)
    print(f"DER Encoded Signature: {der_encoded.hex()}")
    
    # Recovery ID test
    print("\n6. Signature Recovery Test:")
    recovery_id = TransactionSigner.calculate_recovery_id(message_hash, (r, s), private_key)
    recovered_key = TransactionSigner.recover_public_key(message_hash, (r, s), recovery_id)
    
    print(f"Recovery ID: {recovery_id}")
    print(f"Original Public Key: ({hex(public_key[0])}, {hex(public_key[1])})")
    if recovered_key:
        print(f"Recovered Public Key: ({hex(recovered_key[0])}, {hex(recovered_key[1])})")
        print(f"Recovery Successful: {recovered_key == public_key}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_transaction_signing()