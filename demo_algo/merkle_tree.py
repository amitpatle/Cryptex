#!/usr/bin/env python3
"""
Merkle Tree Implementation
=========================

This module demonstrates Merkle tree construction and verification,
which is fundamental to blockchain technology for efficient and secure
verification of large data structures.
"""

import hashlib
from typing import List, Optional, Tuple
import math

class MerkleTree:
    """Merkle tree implementation for blockchain applications"""
    
    def __init__(self, data: List[bytes]):
        """
        Initialize Merkle tree with data
        
        Args:
            data: List of data items to include in tree
        """
        self.data = data
        self.leaves = [self._hash(item) for item in data]
        self.tree = self._build_tree()
        self.root = self.tree[0] if self.tree else None
    
    def _hash(self, data: bytes) -> bytes:
        """Hash function (double SHA-256 like Bitcoin)"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    def _build_tree(self) -> List[List[bytes]]:
        """
        Build complete Merkle tree
        
        Returns:
            List[List[bytes]]: Tree levels from root to leaves
        """
        if not self.leaves:
            return []
        
        tree = []
        current_level = self.leaves.copy()
        
        while len(current_level) > 1:
            tree.append(current_level.copy())
            next_level = []
            
            # Process pairs of nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                
                # If odd number of nodes, duplicate the last one
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left
                
                # Hash the concatenation
                parent = self._hash(left + right)
                next_level.append(parent)
            
            current_level = next_level
        
        # Add root level
        tree.append(current_level)
        
        # Reverse to have root at index 0
        return list(reversed(tree))
    
    def get_root(self) -> Optional[bytes]:
        """Get Merkle root"""
        return self.root
    
    def get_proof(self, index: int) -> List[Tuple[bytes, str]]:
        """
        Generate Merkle proof for data at given index
        
        Args:
            index: Index of data item
            
        Returns:
            List[Tuple[bytes, str]]: List of (hash, position) pairs
                                   position is 'left' or 'right'
        """
        if index >= len(self.data):
            raise IndexError("Index out of range")
        
        proof = []
        current_index = index
        
        # Start from leaves (bottom of tree)
        for level in reversed(self.tree[1:]):  # Skip root level
            # Determine sibling index
            if current_index % 2 == 0:
                # Current node is left child, sibling is right
                sibling_index = current_index + 1
                position = 'right'
            else:
                # Current node is right child, sibling is left
                sibling_index = current_index - 1
                position = 'left'
            
            # Add sibling to proof if it exists
            if sibling_index < len(level):
                proof.append((level[sibling_index], position))
            else:
                # Odd number of nodes, sibling is same as current
                proof.append((level[current_index], position))
            
            # Move to parent level
            current_index = current_index // 2
        
        return proof
    
    def verify_proof(self, data: bytes, index: int, proof: List[Tuple[bytes, str]]) -> bool:
        """
        Verify Merkle proof
        
        Args:
            data: Original data item
            index: Index of data item
            proof: Merkle proof from get_proof()
            
        Returns:
            bool: True if proof is valid
        """
        if not self.root:
            return False
        
        # Start with hash of the data
        current_hash = self._hash(data)
        current_index = index
        
        # Apply proof steps
        for sibling_hash, position in proof:
            if position == 'left':
                # Sibling is left, current is right
                current_hash = self._hash(sibling_hash + current_hash)
            else:
                # Sibling is right, current is left
                current_hash = self._hash(current_hash + sibling_hash)
            
            current_index = current_index // 2
        
        # Final hash should match root
        return current_hash == self.root
    
    def get_tree_info(self) -> dict:
        """Get information about the tree structure"""
        if not self.tree:
            return {'empty': True}
        
        return {
            'empty': False,
            'data_count': len(self.data),
            'leaf_count': len(self.leaves),
            'tree_height': len(self.tree),
            'root_hash': self.root.hex() if self.root else None,
            'total_nodes': sum(len(level) for level in self.tree)
        }
    
    def print_tree(self):
        """Print tree structure for visualization"""
        if not self.tree:
            print("Empty tree")
            return
        
        print("Merkle Tree Structure:")
        print("=" * 50)
        
        for level_idx, level in enumerate(self.tree):
            level_name = "Root" if level_idx == 0 else f"Level {level_idx}"
            if level_idx == len(self.tree) - 1:
                level_name = "Leaves"
            
            print(f"{level_name}:")
            for node_idx, node_hash in enumerate(level):
                print(f"  [{node_idx}] {node_hash.hex()[:16]}...")
            print()


class MerkleTreeOptimized:
    """Optimized Merkle tree for large datasets"""
    
    def __init__(self, data: List[bytes]):
        self.data = data
        self.leaves = [self._hash(item) for item in data]
        self.root = self._calculate_root()
    
    def _hash(self, data: bytes) -> bytes:
        """Hash function"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    def _calculate_root(self) -> Optional[bytes]:
        """Calculate root without storing entire tree"""
        if not self.leaves:
            return None
        
        current_level = self.leaves.copy()
        
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = self._hash(left + right)
                next_level.append(parent)
            
            current_level = next_level
        
        return current_level[0]
    
    def get_proof_optimized(self, index: int) -> List[Tuple[bytes, str]]:
        """Generate proof without storing full tree"""
        if index >= len(self.data):
            raise IndexError("Index out of range")
        
        proof = []
        current_level = self.leaves.copy()
        current_index = index
        
        while len(current_level) > 1:
            # Calculate sibling
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                position = 'right'
            else:
                sibling_index = current_index - 1
                position = 'left'
            
            # Add sibling to proof
            if sibling_index < len(current_level):
                proof.append((current_level[sibling_index], position))
            else:
                proof.append((current_level[current_index], position))
            
            # Calculate next level
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = self._hash(left + right)
                next_level.append(parent)
            
            current_level = next_level
            current_index = current_index // 2
        
        return proof


def demo_merkle_tree():
    """Demonstrate Merkle tree functionality"""
    print("=== Merkle Tree Demo ===\n")
    
    # Create sample transaction data
    transactions = [
        b"Alice sends 10 BTC to Bob",
        b"Bob sends 5 BTC to Charlie", 
        b"Charlie sends 3 BTC to Dave",
        b"Dave sends 1 BTC to Eve",
        b"Eve sends 2 BTC to Frank",
        b"Frank sends 4 BTC to Grace",
        b"Grace sends 6 BTC to Henry",
        b"Henry sends 8 BTC to Alice"
    ]
    
    print("1. Sample Transactions:")
    for i, tx in enumerate(transactions):
        print(f"  TX{i}: {tx.decode()}")
    
    # Build Merkle tree
    print("\n2. Building Merkle Tree:")
    tree = MerkleTree(transactions)
    
    tree_info = tree.get_tree_info()
    print(f"Data items: {tree_info['data_count']}")
    print(f"Tree height: {tree_info['tree_height']}")
    print(f"Total nodes: {tree_info['total_nodes']}")
    print(f"Merkle root: {tree_info['root_hash']}")
    
    # Print tree structure
    print("\n3. Tree Structure:")
    tree.print_tree()
    
    # Generate and verify proofs
    print("4. Merkle Proof Generation and Verification:")
    
    test_indices = [0, 3, 7]  # Test different positions
    
    for index in test_indices:
        print(f"\nTesting TX{index}: {transactions[index].decode()}")
        
        # Generate proof
        proof = tree.get_proof(index)
        print(f"Proof length: {len(proof)} steps")
        
        for step, (hash_val, position) in enumerate(proof):
            print(f"  Step {step}: {hash_val.hex()[:16]}... ({position})")
        
        # Verify proof
        is_valid = tree.verify_proof(transactions[index], index, proof)
        print(f"Proof valid: {is_valid}")
        
        # Test with wrong data
        wrong_data = b"Wrong transaction data"
        is_invalid = tree.verify_proof(wrong_data, index, proof)
        print(f"Wrong data valid: {is_invalid}")
    
    # Test with different tree sizes
    print("\n5. Different Tree Sizes:")
    
    tree_sizes = [1, 2, 3, 4, 5, 7, 8, 15, 16, 17]
    
    for size in tree_sizes:
        test_data = [f"Data item {i}".encode() for i in range(size)]
        test_tree = MerkleTree(test_data)
        info = test_tree.get_tree_info()
        
        print(f"Size {size:2d}: Height {info['tree_height']}, "
              f"Nodes {info['total_nodes']}, "
              f"Root: {info['root_hash'][:16] if info['root_hash'] else 'None'}...")
    
    # Optimized tree comparison
    print("\n6. Optimized vs Standard Tree:")
    
    large_data = [f"Transaction {i}".encode() for i in range(1000)]
    
    import time
    
    # Standard tree
    start_time = time.time()
    standard_tree = MerkleTree(large_data)
    standard_time = time.time() - start_time
    
    # Optimized tree
    start_time = time.time()
    optimized_tree = MerkleTreeOptimized(large_data)
    optimized_time = time.time() - start_time
    
    print(f"Standard tree build time: {standard_time:.4f} seconds")
    print(f"Optimized tree build time: {optimized_time:.4f} seconds")
    print(f"Roots match: {standard_tree.get_root() == optimized_tree.root}")
    
    # Proof generation comparison
    test_index = 500
    
    start_time = time.time()
    standard_proof = standard_tree.get_proof(test_index)
    standard_proof_time = time.time() - start_time
    
    start_time = time.time()
    optimized_proof = optimized_tree.get_proof_optimized(test_index)
    optimized_proof_time = time.time() - start_time
    
    print(f"Standard proof time: {standard_proof_time:.6f} seconds")
    print(f"Optimized proof time: {optimized_proof_time:.6f} seconds")
    print(f"Proof lengths: Standard {len(standard_proof)}, Optimized {len(optimized_proof)}")
    
    # Block header simulation
    print("\n7. Bitcoin Block Header Simulation:")
    
    # Simulate Bitcoin block with transaction Merkle tree
    block_transactions = [
        b"Coinbase: 50 BTC to miner",
        b"Alice -> Bob: 2.5 BTC",
        b"Carol -> Dave: 1.8 BTC", 
        b"Eve -> Frank: 0.7 BTC",
        b"Grace -> Henry: 3.2 BTC"
    ]
    
    block_tree = MerkleTree(block_transactions)
    merkle_root = block_tree.get_root()
    
    # Simulate block header
    block_header = {
        'version': 1,
        'prev_block_hash': '0' * 64,
        'merkle_root': merkle_root.hex(),
        'timestamp': 1234567890,
        'bits': 0x1d00ffff,
        'nonce': 2083236893
    }
    
    print("Block Header:")
    for key, value in block_header.items():
        if key == 'merkle_root':
            print(f"  {key}: {value}")
        else:
            print(f"  {key}: {value}")
    
    print(f"\nBlock contains {len(block_transactions)} transactions")
    print("Anyone can verify a transaction is in this block using only:")
    print("- The transaction data")
    print("- A Merkle proof (log₂(n) hashes)")
    print("- The Merkle root from the block header")
    
    # Demonstrate SPV (Simplified Payment Verification)
    print("\n8. SPV (Simplified Payment Verification) Demo:")
    
    target_tx_index = 2
    target_tx = block_transactions[target_tx_index]
    spv_proof = block_tree.get_proof(target_tx_index)
    
    print(f"Target transaction: {target_tx.decode()}")
    print(f"Merkle root: {merkle_root.hex()}")
    print(f"Proof size: {len(spv_proof)} hashes ({len(spv_proof) * 32} bytes)")
    
    # Verify without downloading full block
    spv_valid = block_tree.verify_proof(target_tx, target_tx_index, spv_proof)
    print(f"SPV verification: {'VALID' if spv_valid else 'INVALID'}")
    
    print(f"\nSPV allows verification with only {len(spv_proof)} hashes")
    print(f"instead of downloading all {len(block_transactions)} transactions!")
    
    # Tree modification detection
    print("\n9. Tree Modification Detection:")
    
    original_data = [b"TX1", b"TX2", b"TX3", b"TX4"]
    original_tree = MerkleTree(original_data)
    original_root = original_tree.get_root()
    
    # Modify one transaction
    modified_data = [b"TX1", b"TX2_MODIFIED", b"TX3", b"TX4"]
    modified_tree = MerkleTree(modified_data)
    modified_root = modified_tree.get_root()
    
    print(f"Original root:  {original_root.hex()}")
    print(f"Modified root:  {modified_root.hex()}")
    print(f"Roots different: {original_root != modified_root}")
    print("Even small changes completely alter the Merkle root!")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_merkle_tree()