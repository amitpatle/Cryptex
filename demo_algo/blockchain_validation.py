#!/usr/bin/env python3
"""
Blockchain Validation Algorithms
===============================

This module demonstrates the validation algorithms used in blockchain
systems for verifying blocks, transactions, and maintaining consensus.
"""

import hashlib
import time
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
import struct

@dataclass
class Transaction:
    """Transaction data structure"""
    txid: str
    inputs: List[Dict]
    outputs: List[Dict]
    version: int = 1
    locktime: int = 0
    size: int = 0
    fee: int = 0

@dataclass
class Block:
    """Block data structure"""
    hash: str
    height: int
    version: int
    prev_block_hash: str
    merkle_root: str
    timestamp: int
    bits: int
    nonce: int
    transactions: List[Transaction]
    size: int = 0
    weight: int = 0

class BlockchainValidator:
    """Blockchain validation algorithms"""
    
    def __init__(self):
        self.max_block_size = 1000000  # 1MB
        self.max_block_weight = 4000000  # 4M weight units
        self.coinbase_maturity = 100  # blocks
        self.max_money = 21000000 * 100000000  # 21M BTC in satoshis
        self.min_tx_fee = 1000  # minimum fee in satoshis
        self.difficulty_adjustment_interval = 2016  # blocks
        self.target_block_time = 600  # 10 minutes in seconds
    
    def validate_transaction(self, tx: Transaction, utxo_set: Dict[str, Dict]) -> Tuple[bool, str]:
        """
        Validate a single transaction
        
        Args:
            tx: Transaction to validate
            utxo_set: Available UTXOs {txid:vout -> {amount, script, ...}}
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Basic format validation
        if not tx.txid or len(tx.txid) != 64:
            return False, "Invalid transaction ID format"
        
        if not tx.inputs and not self._is_coinbase_tx(tx):
            return False, "Non-coinbase transaction must have inputs"
        
        if not tx.outputs:
            return False, "Transaction must have outputs"
        
        # Coinbase transaction validation
        if self._is_coinbase_tx(tx):
            return self._validate_coinbase_transaction(tx)
        
        # Input validation
        total_input_value = 0
        for inp in tx.inputs:
            utxo_key = f"{inp['prev_txid']}:{inp['prev_vout']}"
            
            # Check if UTXO exists
            if utxo_key not in utxo_set:
                return False, f"UTXO not found: {utxo_key}"
            
            utxo = utxo_set[utxo_key]
            total_input_value += utxo['amount']
            
            # Validate script signature (simplified)
            if not self._validate_script_signature(inp, utxo):
                return False, f"Invalid signature for input {utxo_key}"
        
        # Output validation
        total_output_value = 0
        for i, output in enumerate(tx.outputs):
            if output['amount'] < 0:
                return False, f"Negative output value in output {i}"
            
            if output['amount'] > self.max_money:
                return False, f"Output value too large in output {i}"
            
            total_output_value += output['amount']
            
            # Validate output script
            if not self._validate_output_script(output):
                return False, f"Invalid output script in output {i}"
        
        # Fee validation
        if total_input_value < total_output_value:
            return False, "Input value less than output value"
        
        fee = total_input_value - total_output_value
        if fee < 0:
            return False, "Negative transaction fee"
        
        # Store fee for block validation
        tx.fee = fee
        
        # Check for dust outputs
        for i, output in enumerate(tx.outputs):
            if output['amount'] < 546:  # Dust threshold
                return False, f"Dust output in output {i}"
        
        return True, "Valid transaction"
    
    def validate_block(self, block: Block, prev_block: Optional[Block], 
                      utxo_set: Dict[str, Dict]) -> Tuple[bool, str]:
        """
        Validate a complete block
        
        Args:
            block: Block to validate
            prev_block: Previous block in chain
            utxo_set: Current UTXO set
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Basic block structure validation
        if not block.transactions:
            return False, "Block must contain at least one transaction"
        
        # First transaction must be coinbase
        if not self._is_coinbase_tx(block.transactions[0]):
            return False, "First transaction must be coinbase"
        
        # Only first transaction can be coinbase
        for i, tx in enumerate(block.transactions[1:], 1):
            if self._is_coinbase_tx(tx):
                return False, f"Non-first transaction {i} is coinbase"
        
        # Block size validation
        if block.size > self.max_block_size:
            return False, f"Block size {block.size} exceeds maximum {self.max_block_size}"
        
        # Block weight validation (for SegWit)
        if block.weight > self.max_block_weight:
            return False, f"Block weight {block.weight} exceeds maximum {self.max_block_weight}"
        
        # Previous block hash validation
        if prev_block and block.prev_block_hash != prev_block.hash:
            return False, "Previous block hash mismatch"
        
        # Block hash validation
        calculated_hash = self._calculate_block_hash(block)
        if calculated_hash != block.hash:
            return False, "Block hash mismatch"
        
        # Proof of work validation
        if not self._validate_proof_of_work(block):
            return False, "Invalid proof of work"
        
        # Timestamp validation
        if not self._validate_timestamp(block, prev_block):
            return False, "Invalid timestamp"
        
        # Merkle root validation
        if not self._validate_merkle_root(block):
            return False, "Invalid Merkle root"
        
        # Transaction validation
        total_fees = 0
        temp_utxo_set = utxo_set.copy()
        
        for i, tx in enumerate(block.transactions):
            is_valid, error = self.validate_transaction(tx, temp_utxo_set)
            if not is_valid:
                return False, f"Invalid transaction {i}: {error}"
            
            # Update UTXO set for subsequent transactions
            if not self._is_coinbase_tx(tx):
                # Remove spent UTXOs
                for inp in tx.inputs:
                    utxo_key = f"{inp['prev_txid']}:{inp['prev_vout']}"
                    if utxo_key in temp_utxo_set:
                        del temp_utxo_set[utxo_key]
                
                total_fees += tx.fee
            
            # Add new UTXOs
            for j, output in enumerate(tx.outputs):
                utxo_key = f"{tx.txid}:{j}"
                temp_utxo_set[utxo_key] = {
                    'amount': output['amount'],
                    'script': output.get('script', ''),
                    'address': output.get('address', '')
                }
        
        # Coinbase reward validation
        coinbase_tx = block.transactions[0]
        block_reward = self._calculate_block_reward(block.height)
        expected_coinbase_value = block_reward + total_fees
        
        actual_coinbase_value = sum(output['amount'] for output in coinbase_tx.outputs)
        if actual_coinbase_value > expected_coinbase_value:
            return False, f"Coinbase value {actual_coinbase_value} exceeds allowed {expected_coinbase_value}"
        
        return True, "Valid block"
    
    def validate_chain(self, blocks: List[Block]) -> Tuple[bool, str]:
        """
        Validate an entire blockchain
        
        Args:
            blocks: List of blocks in chronological order
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not blocks:
            return False, "Empty blockchain"
        
        # Genesis block validation
        genesis = blocks[0]
        if genesis.height != 0:
            return False, "Genesis block height must be 0"
        
        if genesis.prev_block_hash != "0" * 64:
            return False, "Genesis block must have null previous hash"
        
        # Initialize UTXO set with genesis block
        utxo_set = {}
        self._update_utxo_set(utxo_set, genesis)
        
        # Validate each subsequent block
        for i in range(1, len(blocks)):
            current_block = blocks[i]
            prev_block = blocks[i - 1]
            
            # Height validation
            if current_block.height != prev_block.height + 1:
                return False, f"Block {i} height mismatch"
            
            # Validate block
            is_valid, error = self.validate_block(current_block, prev_block, utxo_set)
            if not is_valid:
                return False, f"Block {i} validation failed: {error}"
            
            # Update UTXO set
            self._update_utxo_set(utxo_set, current_block)
        
        # Additional chain validation
        if not self._validate_difficulty_adjustment(blocks):
            return False, "Invalid difficulty adjustment"
        
        return True, "Valid blockchain"
    
    def _is_coinbase_tx(self, tx: Transaction) -> bool:
        """Check if transaction is coinbase"""
        return (len(tx.inputs) == 1 and 
                tx.inputs[0].get('prev_txid') == "0" * 64 and 
                tx.inputs[0].get('prev_vout') == 0xffffffff)
    
    def _validate_coinbase_transaction(self, tx: Transaction) -> Tuple[bool, str]:
        """Validate coinbase transaction"""
        if len(tx.inputs) != 1:
            return False, "Coinbase must have exactly one input"
        
        coinbase_input = tx.inputs[0]
        if (coinbase_input.get('prev_txid') != "0" * 64 or 
            coinbase_input.get('prev_vout') != 0xffffffff):
            return False, "Invalid coinbase input"
        
        # Coinbase script length validation
        script_sig = coinbase_input.get('script_sig', '')
        if len(script_sig) < 2 or len(script_sig) > 100:
            return False, "Invalid coinbase script length"
        
        return True, "Valid coinbase transaction"
    
    def _validate_script_signature(self, inp: Dict, utxo: Dict) -> bool:
        """Validate script signature (simplified)"""
        # This is a simplified validation
        # In reality, this would involve complex script execution
        return 'script_sig' in inp and len(inp['script_sig']) > 0
    
    def _validate_output_script(self, output: Dict) -> bool:
        """Validate output script"""
        # Simplified validation
        return 'script' in output and len(output['script']) > 0
    
    def _calculate_block_hash(self, block: Block) -> str:
        """Calculate block hash from header"""
        # Serialize block header
        header = struct.pack('<I', block.version)
        header += bytes.fromhex(block.prev_block_hash)[::-1]  # Reverse for little-endian
        header += bytes.fromhex(block.merkle_root)[::-1]
        header += struct.pack('<I', block.timestamp)
        header += struct.pack('<I', block.bits)
        header += struct.pack('<I', block.nonce)
        
        # Double SHA-256
        hash_result = hashlib.sha256(hashlib.sha256(header).digest()).digest()
        
        # Reverse for big-endian display
        return hash_result[::-1].hex()
    
    def _validate_proof_of_work(self, block: Block) -> bool:
        """Validate proof of work"""
        # Calculate target from bits
        target = self._bits_to_target(block.bits)
        
        # Convert block hash to integer
        block_hash_int = int(block.hash, 16)
        
        # Hash must be less than target
        return block_hash_int < target
    
    def _bits_to_target(self, bits: int) -> int:
        """Convert compact bits representation to target"""
        exponent = bits >> 24
        mantissa = bits & 0xffffff
        
        if exponent <= 3:
            target = mantissa >> (8 * (3 - exponent))
        else:
            target = mantissa << (8 * (exponent - 3))
        
        return target
    
    def _validate_timestamp(self, block: Block, prev_block: Optional[Block]) -> bool:
        """Validate block timestamp"""
        current_time = int(time.time())
        
        # Block timestamp cannot be too far in the future
        if block.timestamp > current_time + 2 * 60 * 60:  # 2 hours
            return False
        
        # Block timestamp must be greater than previous block
        if prev_block and block.timestamp <= prev_block.timestamp:
            return False
        
        return True
    
    def _validate_merkle_root(self, block: Block) -> str:
        """Validate Merkle root"""
        # Calculate Merkle root from transactions
        tx_hashes = [bytes.fromhex(tx.txid)[::-1] for tx in block.transactions]
        calculated_root = self._calculate_merkle_root(tx_hashes)
        
        return calculated_root.hex() == block.merkle_root
    
    def _calculate_merkle_root(self, hashes: List[bytes]) -> bytes:
        """Calculate Merkle root"""
        if not hashes:
            return b'\x00' * 32
        
        if len(hashes) == 1:
            return hashes[0]
        
        # Ensure even number of hashes
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        
        # Calculate next level
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            next_level.append(hashlib.sha256(hashlib.sha256(combined).digest()).digest())
        
        return self._calculate_merkle_root(next_level)
    
    def _calculate_block_reward(self, height: int) -> int:
        """Calculate block reward based on height"""
        # Bitcoin halving every 210,000 blocks
        halvings = height // 210000
        if halvings >= 64:
            return 0
        
        reward = 5000000000  # 50 BTC in satoshis
        return reward >> halvings
    
    def _update_utxo_set(self, utxo_set: Dict[str, Dict], block: Block):
        """Update UTXO set with block transactions"""
        for tx in block.transactions:
            # Remove spent UTXOs
            if not self._is_coinbase_tx(tx):
                for inp in tx.inputs:
                    utxo_key = f"{inp['prev_txid']}:{inp['prev_vout']}"
                    if utxo_key in utxo_set:
                        del utxo_set[utxo_key]
            
            # Add new UTXOs
            for i, output in enumerate(tx.outputs):
                utxo_key = f"{tx.txid}:{i}"
                utxo_set[utxo_key] = {
                    'amount': output['amount'],
                    'script': output.get('script', ''),
                    'address': output.get('address', '')
                }
    
    def _validate_difficulty_adjustment(self, blocks: List[Block]) -> bool:
        """Validate difficulty adjustments"""
        # Simplified validation - check that difficulty adjustments occur
        # at proper intervals and are within acceptable bounds
        
        for i in range(self.difficulty_adjustment_interval, len(blocks), 
                      self.difficulty_adjustment_interval):
            if i >= len(blocks):
                break
            
            # Get blocks for difficulty calculation
            start_block = blocks[i - self.difficulty_adjustment_interval]
            end_block = blocks[i - 1]
            
            # Calculate actual time taken
            actual_time = end_block.timestamp - start_block.timestamp
            expected_time = self.difficulty_adjustment_interval * self.target_block_time
            
            # Difficulty should adjust to maintain target block time
            # This is a simplified check
            if actual_time < expected_time // 4 or actual_time > expected_time * 4:
                # Difficulty adjustment should have occurred
                if blocks[i].bits == blocks[i - 1].bits:
                    return False
        
        return True


def demo_blockchain_validation():
    """Demonstrate blockchain validation algorithms"""
    print("=== Blockchain Validation Demo ===\n")
    
    validator = BlockchainValidator()
    
    # Create sample transactions
    print("1. Transaction Validation:")
    
    # Valid transaction
    valid_tx = Transaction(
        txid="a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
        inputs=[{
            'prev_txid': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            'prev_vout': 0,
            'script_sig': '304402201234567890abcdef...'
        }],
        outputs=[
            {
                'amount': 5000000000,  # 50 BTC
                'script': '76a914' + '0' * 40 + '88ac',
                'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
            },
            {
                'amount': 2500000000,  # 25 BTC (change)
                'script': '76a914' + '1' * 40 + '88ac', 
                'address': '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
            }
        ]
    )
    
    # Sample UTXO set
    utxo_set = {
        '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:0': {
            'amount': 7500000000,  # 75 BTC
            'script': '76a914' + '2' * 40 + '88ac',
            'address': '1C1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        }
    }
    
    is_valid, error = validator.validate_transaction(valid_tx, utxo_set)
    print(f"Valid transaction: {is_valid}")
    if not is_valid:
        print(f"Error: {error}")
    else:
        print(f"Transaction fee: {valid_tx.fee:,} satoshis")
    
    # Invalid transaction (insufficient funds)
    invalid_tx = Transaction(
        txid="b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1",
        inputs=[{
            'prev_txid': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            'prev_vout': 0,
            'script_sig': '304402201234567890abcdef...'
        }],
        outputs=[{
            'amount': 10000000000,  # 100 BTC (more than input)
            'script': '76a914' + '3' * 40 + '88ac',
            'address': '1D1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        }]
    )
    
    is_valid, error = validator.validate_transaction(invalid_tx, utxo_set)
    print(f"Invalid transaction: {is_valid}")
    print(f"Error: {error}")
    
    # Block validation
    print("\n2. Block Validation:")
    
    # Create coinbase transaction
    coinbase_tx = Transaction(
        txid="coinbase1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        inputs=[{
            'prev_txid': '0' * 64,
            'prev_vout': 0xffffffff,
            'script_sig': '03123456'  # Block height in script
        }],
        outputs=[{
            'amount': 5000000000,  # 50 BTC block reward
            'script': '76a914' + '4' * 40 + '88ac',
            'address': '1E1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        }]
    )
    
    # Create sample block
    sample_block = Block(
        hash="00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        height=1,
        version=1,
        prev_block_hash="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        merkle_root="0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
        timestamp=1231469665,
        bits=0x1d00ffff,
        nonce=2573394689,
        transactions=[coinbase_tx, valid_tx],
        size=285,
        weight=1140
    )
    
    # Create previous block (genesis)
    genesis_block = Block(
        hash="000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        height=0,
        version=1,
        prev_block_hash="0" * 64,
        merkle_root="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        timestamp=1231006505,
        bits=0x1d00ffff,
        nonce=2083236893,
        transactions=[Transaction(
            txid="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            inputs=[{
                'prev_txid': '0' * 64,
                'prev_vout': 0xffffffff,
                'script_sig': '04ffff001d0104'
            }],
            outputs=[{
                'amount': 5000000000,
                'script': '76a914' + '5' * 40 + '88ac',
                'address': '1F1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
            }]
        )],
        size=285,
        weight=1140
    )
    
    # Update UTXO set with genesis block
    validator._update_utxo_set(utxo_set, genesis_block)
    
    is_valid, error = validator.validate_block(sample_block, genesis_block, utxo_set)
    print(f"Block validation: {is_valid}")
    if not is_valid:
        print(f"Error: {error}")
    
    # Chain validation
    print("\n3. Blockchain Validation:")
    
    blockchain = [genesis_block, sample_block]
    is_valid, error = validator.validate_chain(blockchain)
    print(f"Blockchain validation: {is_valid}")
    if not is_valid:
        print(f"Error: {error}")
    
    # Proof of work demonstration
    print("\n4. Proof of Work Validation:")
    
    def demonstrate_pow():
        # Show how proof of work validation works
        target = validator._bits_to_target(sample_block.bits)
        block_hash_int = int(sample_block.hash, 16)
        
        print(f"Block hash: {sample_block.hash}")
        print(f"Target:     {target:064x}")
        print(f"Hash < Target: {block_hash_int < target}")
        print(f"Leading zeros in hash: {len(sample_block.hash) - len(sample_block.hash.lstrip('0'))}")
    
    demonstrate_pow()
    
    # Difficulty adjustment simulation
    print("\n5. Difficulty Adjustment Simulation:")
    
    def simulate_difficulty_adjustment():
        # Simulate blocks with different timing
        blocks = [genesis_block]
        current_bits = genesis_block.bits
        
        for i in range(1, 10):
            # Simulate faster block times (should increase difficulty)
            timestamp = blocks[-1].timestamp + 300  # 5 minutes instead of 10
            
            new_block = Block(
                hash=f"{'0' * (8 + i)}{'1' * (56 - i)}",
                height=i,
                version=1,
                prev_block_hash=blocks[-1].hash,
                merkle_root="0" * 64,
                timestamp=timestamp,
                bits=current_bits,
                nonce=12345,
                transactions=[Transaction(
                    txid=f"tx{i:02d}" + "0" * 60,
                    inputs=[{'prev_txid': '0' * 64, 'prev_vout': 0xffffffff, 'script_sig': f'0{i}'}],
                    outputs=[{'amount': 5000000000, 'script': '76a914' + '0' * 40 + '88ac', 'address': '1' + '0' * 33}]
                )],
                size=200,
                weight=800
            )
            
            blocks.append(new_block)
        
        print(f"Simulated {len(blocks)} blocks")
        print(f"Average block time: {(blocks[-1].timestamp - blocks[0].timestamp) / (len(blocks) - 1):.0f} seconds")
        print("In real Bitcoin, difficulty would adjust to maintain 10-minute average")
    
    simulate_difficulty_adjustment()
    
    # Transaction validation edge cases
    print("\n6. Transaction Validation Edge Cases:")
    
    edge_cases = [
        {
            'name': 'Double spend attempt',
            'tx': Transaction(
                txid="double_spend_tx" + "0" * 48,
                inputs=[{
                    'prev_txid': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
                    'prev_vout': 0,  # Same UTXO as valid_tx
                    'script_sig': '304402201234567890abcdef...'
                }],
                outputs=[{
                    'amount': 7500000000,
                    'script': '76a914' + '6' * 40 + '88ac',
                    'address': '1G1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
                }]
            )
        },
        {
            'name': 'Negative output',
            'tx': Transaction(
                txid="negative_output_tx" + "0" * 46,
                inputs=[{
                    'prev_txid': 'unused_utxo' + "0" * 52,
                    'prev_vout': 0,
                    'script_sig': '304402201234567890abcdef...'
                }],
                outputs=[{
                    'amount': -1000000,  # Negative amount
                    'script': '76a914' + '7' * 40 + '88ac',
                    'address': '1H1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
                }]
            )
        }
    ]
    
    # Add unused UTXO for testing
    test_utxo_set = utxo_set.copy()
    test_utxo_set['unused_utxo' + "0" * 52 + ':0'] = {
        'amount': 1000000,
        'script': '76a914' + '8' * 40 + '88ac',
        'address': '1I1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
    }
    
    for case in edge_cases:
        is_valid, error = validator.validate_transaction(case['tx'], test_utxo_set)
        print(f"{case['name']}: {'VALID' if is_valid else 'INVALID'}")
        if not is_valid:
            print(f"  Reason: {error}")
    
    # Validation performance
    print("\n7. Validation Performance:")
    
    import time
    
    # Time transaction validation
    start_time = time.time()
    for _ in range(1000):
        validator.validate_transaction(valid_tx, utxo_set)
    tx_time = (time.time() - start_time) / 1000
    
    print(f"Average transaction validation time: {tx_time:.6f} seconds")
    print(f"Transactions per second: {1/tx_time:.0f}")
    
    # Memory usage estimation
    utxo_count = len(utxo_set)
    estimated_memory = utxo_count * 100  # Rough estimate: 100 bytes per UTXO
    print(f"UTXO set size: {utxo_count:,} entries")
    print(f"Estimated memory usage: {estimated_memory:,} bytes ({estimated_memory/1024/1024:.1f} MB)")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_blockchain_validation()