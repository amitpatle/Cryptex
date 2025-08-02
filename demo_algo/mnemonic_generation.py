#!/usr/bin/env python3
"""
BIP39 Mnemonic Phrase Generation
===============================

This module demonstrates the BIP39 standard for generating mnemonic phrases
from entropy and deriving seeds for hierarchical deterministic wallets.
"""

import hashlib
import secrets
from typing import List, Optional
import unicodedata

class MnemonicGenerator:
    """BIP39 mnemonic phrase generator"""
    
    # BIP39 English wordlist (first 100 words for demo - full list has 2048 words)
    WORDLIST = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
        "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
        "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
        "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
        "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
        "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
        "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
        "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "article",
        "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume"
    ]
    
    @staticmethod
    def generate_entropy(strength: int = 128) -> bytes:
        """
        Generate cryptographically secure entropy
        
        Args:
            strength: Entropy strength in bits (128, 160, 192, 224, or 256)
            
        Returns:
            bytes: Random entropy
        """
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("Strength must be 128, 160, 192, 224, or 256 bits")
        
        return secrets.token_bytes(strength // 8)
    
    @staticmethod
    def entropy_to_mnemonic(entropy: bytes) -> List[str]:
        """
        Convert entropy to mnemonic phrase according to BIP39
        
        Args:
            entropy: Entropy bytes (16, 20, 24, 28, or 32 bytes)
            
        Returns:
            List[str]: Mnemonic words
        """
        entropy_length = len(entropy)
        if entropy_length not in [16, 20, 24, 28, 32]:
            raise ValueError("Entropy must be 16, 20, 24, 28, or 32 bytes")
        
        # Calculate checksum
        checksum_length = entropy_length // 4  # bits
        hash_bytes = hashlib.sha256(entropy).digest()
        checksum = hash_bytes[0]
        
        # Convert entropy to binary
        entropy_bits = ''.join(format(byte, '08b') for byte in entropy)
        
        # Add checksum bits
        checksum_bits = format(checksum, '08b')[:checksum_length]
        total_bits = entropy_bits + checksum_bits
        
        # Split into 11-bit groups
        words = []
        for i in range(0, len(total_bits), 11):
            word_bits = total_bits[i:i+11]
            if len(word_bits) == 11:
                word_index = int(word_bits, 2)
                # Use modulo to handle our limited wordlist
                words.append(MnemonicGenerator.WORDLIST[word_index % len(MnemonicGenerator.WORDLIST)])
        
        return words
    
    @staticmethod
    def mnemonic_to_seed(mnemonic: List[str], passphrase: str = "") -> bytes:
        """
        Convert mnemonic phrase to seed using PBKDF2
        
        Args:
            mnemonic: List of mnemonic words
            passphrase: Optional passphrase
            
        Returns:
            bytes: 64-byte seed
        """
        # Join mnemonic words with spaces
        mnemonic_str = " ".join(mnemonic)
        
        # Normalize using NFKD
        mnemonic_bytes = unicodedata.normalize('NFKD', mnemonic_str).encode('utf-8')
        
        # Create salt
        salt = "mnemonic" + passphrase
        salt_bytes = unicodedata.normalize('NFKD', salt).encode('utf-8')
        
        # Use PBKDF2 with 2048 iterations
        seed = hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, salt_bytes, 2048)
        
        return seed
    
    @staticmethod
    def validate_mnemonic(mnemonic: List[str]) -> bool:
        """
        Validate mnemonic phrase checksum
        
        Args:
            mnemonic: List of mnemonic words
            
        Returns:
            bool: True if valid
        """
        try:
            # Convert words back to indices
            indices = []
            for word in mnemonic:
                if word not in MnemonicGenerator.WORDLIST:
                    return False
                indices.append(MnemonicGenerator.WORDLIST.index(word))
            
            # Convert indices to binary
            total_bits = ''.join(format(index, '011b') for index in indices)
            
            # Calculate expected lengths
            total_length = len(total_bits)
            checksum_length = total_length // 33  # 1 bit per 32 bits of entropy
            entropy_length = total_length - checksum_length
            
            # Split entropy and checksum
            entropy_bits = total_bits[:entropy_length]
            checksum_bits = total_bits[entropy_length:]
            
            # Convert entropy bits to bytes
            entropy_bytes = bytearray()
            for i in range(0, len(entropy_bits), 8):
                byte_bits = entropy_bits[i:i+8]
                if len(byte_bits) == 8:
                    entropy_bytes.append(int(byte_bits, 2))
            
            # Calculate expected checksum
            hash_bytes = hashlib.sha256(entropy_bytes).digest()
            expected_checksum = format(hash_bytes[0], '08b')[:checksum_length]
            
            return checksum_bits == expected_checksum
            
        except Exception:
            return False
    
    @staticmethod
    def generate_mnemonic(strength: int = 128, passphrase: str = "") -> tuple:
        """
        Generate complete mnemonic phrase and seed
        
        Args:
            strength: Entropy strength in bits
            passphrase: Optional passphrase
            
        Returns:
            tuple: (mnemonic_words, seed, entropy)
        """
        # Generate entropy
        entropy = MnemonicGenerator.generate_entropy(strength)
        
        # Convert to mnemonic
        mnemonic = MnemonicGenerator.entropy_to_mnemonic(entropy)
        
        # Generate seed
        seed = MnemonicGenerator.mnemonic_to_seed(mnemonic, passphrase)
        
        return mnemonic, seed, entropy
    
    @staticmethod
    def mnemonic_strength_info(word_count: int) -> dict:
        """
        Get information about mnemonic strength
        
        Args:
            word_count: Number of words in mnemonic
            
        Returns:
            dict: Strength information
        """
        strength_map = {
            12: {'entropy_bits': 128, 'checksum_bits': 4, 'security': 'Good'},
            15: {'entropy_bits': 160, 'checksum_bits': 5, 'security': 'Better'},
            18: {'entropy_bits': 192, 'checksum_bits': 6, 'security': 'Very Good'},
            21: {'entropy_bits': 224, 'checksum_bits': 7, 'security': 'Excellent'},
            24: {'entropy_bits': 256, 'checksum_bits': 8, 'security': 'Maximum'}
        }
        
        if word_count not in strength_map:
            return {'error': 'Invalid word count'}
        
        info = strength_map[word_count].copy()
        info['total_combinations'] = 2 ** info['entropy_bits']
        info['word_count'] = word_count
        
        return info
    
    @staticmethod
    def create_brain_wallet(passphrase: str) -> tuple:
        """
        Create a brain wallet from a passphrase (NOT RECOMMENDED for real use)
        
        Args:
            passphrase: User passphrase
            
        Returns:
            tuple: (mnemonic, seed)
        """
        # Hash passphrase to create entropy
        entropy = hashlib.sha256(passphrase.encode('utf-8')).digest()[:16]  # 128 bits
        
        # Convert to mnemonic
        mnemonic = MnemonicGenerator.entropy_to_mnemonic(entropy)
        
        # Generate seed
        seed = MnemonicGenerator.mnemonic_to_seed(mnemonic)
        
        return mnemonic, seed
    
    @staticmethod
    def split_mnemonic(mnemonic: List[str], threshold: int, shares: int) -> List[List[str]]:
        """
        Simple mnemonic splitting (Shamir's Secret Sharing concept)
        Note: This is a simplified demonstration, not cryptographically secure
        
        Args:
            mnemonic: Original mnemonic
            threshold: Minimum shares needed to reconstruct
            shares: Total number of shares to create
            
        Returns:
            List[List[str]]: List of mnemonic shares
        """
        if threshold > shares:
            raise ValueError("Threshold cannot be greater than shares")
        
        # Convert mnemonic to seed
        seed = MnemonicGenerator.mnemonic_to_seed(mnemonic)
        
        # Simple XOR-based splitting (for demonstration only)
        shares_list = []
        
        for i in range(shares):
            # Generate random share
            if i < shares - 1:
                share_entropy = secrets.token_bytes(16)
            else:
                # Last share is XOR of all previous shares with original
                share_entropy = seed[:16]
                for j in range(shares - 1):
                    share_seed = MnemonicGenerator.mnemonic_to_seed(shares_list[j])
                    share_entropy = bytes(a ^ b for a, b in zip(share_entropy, share_seed[:16]))
            
            share_mnemonic = MnemonicGenerator.entropy_to_mnemonic(share_entropy)
            shares_list.append(share_mnemonic)
        
        return shares_list


def demo_mnemonic_generation():
    """Demonstrate mnemonic generation algorithms"""
    print("=== BIP39 Mnemonic Generation Demo ===\n")
    
    # Generate mnemonic phrases of different strengths
    print("1. Mnemonic Generation (Different Strengths):")
    
    strengths = [128, 160, 192, 224, 256]
    for strength in strengths:
        mnemonic, seed, entropy = MnemonicGenerator.generate_mnemonic(strength)
        word_count = len(mnemonic)
        
        print(f"\n{strength}-bit entropy ({word_count} words):")
        print(f"  Entropy: {entropy.hex()}")
        print(f"  Mnemonic: {' '.join(mnemonic)}")
        print(f"  Seed: {seed.hex()[:32]}...")
        
        # Validate the mnemonic
        is_valid = MnemonicGenerator.validate_mnemonic(mnemonic)
        print(f"  Valid: {is_valid}")
    
    # Demonstrate mnemonic with passphrase
    print("\n2. Mnemonic with Passphrase:")
    mnemonic, seed_no_pass, _ = MnemonicGenerator.generate_mnemonic(128)
    seed_with_pass = MnemonicGenerator.mnemonic_to_seed(mnemonic, "my_secret_passphrase")
    
    print(f"Mnemonic: {' '.join(mnemonic)}")
    print(f"Seed (no passphrase):   {seed_no_pass.hex()[:32]}...")
    print(f"Seed (with passphrase): {seed_with_pass.hex()[:32]}...")
    print(f"Seeds are different: {seed_no_pass != seed_with_pass}")
    
    # Mnemonic strength information
    print("\n3. Mnemonic Strength Information:")
    for word_count in [12, 15, 18, 21, 24]:
        info = MnemonicGenerator.mnemonic_strength_info(word_count)
        print(f"{word_count:2d} words: {info['entropy_bits']:3d} entropy bits, "
              f"{info['checksum_bits']} checksum bits, "
              f"Security: {info['security']}")
        print(f"          Combinations: 2^{info['entropy_bits']} = {info['total_combinations']:,}")
    
    # Mnemonic validation
    print("\n4. Mnemonic Validation:")
    
    # Valid mnemonic
    valid_mnemonic, _, _ = MnemonicGenerator.generate_mnemonic(128)
    print(f"Valid mnemonic: {' '.join(valid_mnemonic)}")
    print(f"Validation result: {MnemonicGenerator.validate_mnemonic(valid_mnemonic)}")
    
    # Invalid mnemonic (corrupted)
    invalid_mnemonic = valid_mnemonic.copy()
    invalid_mnemonic[0] = "invalid_word"
    print(f"Invalid mnemonic: {' '.join(invalid_mnemonic)}")
    print(f"Validation result: {MnemonicGenerator.validate_mnemonic(invalid_mnemonic)}")
    
    # Brain wallet demonstration (NOT RECOMMENDED)
    print("\n5. Brain Wallet (Educational Only - NOT RECOMMENDED):")
    passphrase = "This is my super secret passphrase that I will never forget"
    brain_mnemonic, brain_seed = MnemonicGenerator.create_brain_wallet(passphrase)
    
    print(f"Passphrase: {passphrase}")
    print(f"Brain wallet mnemonic: {' '.join(brain_mnemonic)}")
    print(f"Brain wallet seed: {brain_seed.hex()[:32]}...")
    print("WARNING: Brain wallets are not secure and should not be used!")
    
    # Mnemonic splitting demonstration
    print("\n6. Mnemonic Splitting (Simplified Demo):")
    original_mnemonic, _, _ = MnemonicGenerator.generate_mnemonic(128)
    
    print(f"Original mnemonic: {' '.join(original_mnemonic)}")
    
    # Split into 3 shares, requiring 2 to reconstruct
    shares = MnemonicGenerator.split_mnemonic(original_mnemonic, 2, 3)
    
    print("Shares:")
    for i, share in enumerate(shares):
        print(f"  Share {i+1}: {' '.join(share)}")
    
    print("Note: This is a simplified demonstration of secret sharing concepts.")
    
    # Entropy analysis
    print("\n7. Entropy Analysis:")
    
    # Generate multiple mnemonics and analyze entropy distribution
    entropy_samples = []
    for _ in range(10):
        _, _, entropy = MnemonicGenerator.generate_mnemonic(128)
        entropy_samples.append(entropy)
    
    print("Entropy samples (first 8 bytes):")
    for i, entropy in enumerate(entropy_samples):
        print(f"  Sample {i+1:2d}: {entropy[:8].hex()}")
    
    # Check for uniqueness
    unique_entropies = set(entropy_samples)
    print(f"Unique samples: {len(unique_entropies)}/{len(entropy_samples)}")
    
    # Seed derivation timing
    print("\n8. Seed Derivation Performance:")
    import time
    
    test_mnemonic, _, _ = MnemonicGenerator.generate_mnemonic(128)
    
    # Time seed generation
    start_time = time.time()
    for _ in range(10):
        MnemonicGenerator.mnemonic_to_seed(test_mnemonic)
    end_time = time.time()
    
    avg_time = (end_time - start_time) / 10
    print(f"Average seed derivation time: {avg_time:.4f} seconds")
    print("Note: PBKDF2 with 2048 iterations is intentionally slow for security")
    
    # Word list statistics
    print("\n9. Word List Statistics:")
    print(f"Total words in demo list: {len(MnemonicGenerator.WORDLIST)}")
    print(f"Bits per word: {11}")  # BIP39 uses 11 bits per word
    print(f"Full BIP39 list has: 2048 words")
    print(f"Each word represents: 2^11 = 2048 possibilities")
    
    # Sample words from different positions
    print("Sample words from list:")
    for i in [0, 25, 50, 75, 99]:
        if i < len(MnemonicGenerator.WORDLIST):
            print(f"  Position {i:2d}: {MnemonicGenerator.WORDLIST[i]}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_mnemonic_generation()