#!/usr/bin/env python3
"""
Balance Calculation and UTXO Management Algorithms
=================================================

This module demonstrates algorithms for calculating cryptocurrency balances,
managing UTXOs (Unspent Transaction Outputs), and tracking transaction history.
"""

import hashlib
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import json

@dataclass
class UTXO:
    """Unspent Transaction Output"""
    txid: str
    vout: int
    amount: int  # Amount in satoshis
    script_pubkey: bytes
    address: str
    confirmations: int
    block_height: Optional[int] = None
    timestamp: Optional[int] = None

@dataclass
class Transaction:
    """Transaction data structure"""
    txid: str
    inputs: List[Dict]
    outputs: List[Dict]
    block_height: Optional[int]
    timestamp: int
    confirmations: int
    fee: int

class BalanceCalculator:
    """Calculate and manage cryptocurrency balances"""
    
    def __init__(self):
        self.utxos: Dict[str, List[UTXO]] = {}  # address -> UTXOs
        self.transactions: Dict[str, Transaction] = {}  # txid -> Transaction
        self.address_history: Dict[str, List[str]] = {}  # address -> txid list
    
    def add_transaction(self, transaction: Transaction):
        """Add transaction to the calculator"""
        self.transactions[transaction.txid] = transaction
        
        # Process inputs (remove UTXOs)
        for inp in transaction.inputs:
            prev_txid = inp['prev_txid']
            prev_vout = inp['prev_vout']
            address = inp.get('address')
            
            if address and address in self.utxos:
                # Remove spent UTXO
                self.utxos[address] = [
                    utxo for utxo in self.utxos[address]
                    if not (utxo.txid == prev_txid and utxo.vout == prev_vout)
                ]
        
        # Process outputs (add new UTXOs)
        for i, output in enumerate(transaction.outputs):
            address = output.get('address')
            if address:
                utxo = UTXO(
                    txid=transaction.txid,
                    vout=i,
                    amount=output['amount'],
                    script_pubkey=bytes.fromhex(output.get('script_pubkey', '')),
                    address=address,
                    confirmations=transaction.confirmations,
                    block_height=transaction.block_height,
                    timestamp=transaction.timestamp
                )
                
                if address not in self.utxos:
                    self.utxos[address] = []
                self.utxos[address].append(utxo)
                
                # Update address history
                if address not in self.address_history:
                    self.address_history[address] = []
                if transaction.txid not in self.address_history[address]:
                    self.address_history[address].append(transaction.txid)
    
    def get_balance(self, address: str, min_confirmations: int = 1) -> int:
        """
        Get confirmed balance for an address
        
        Args:
            address: Bitcoin address
            min_confirmations: Minimum confirmations required
            
        Returns:
            int: Balance in satoshis
        """
        if address not in self.utxos:
            return 0
        
        balance = 0
        for utxo in self.utxos[address]:
            if utxo.confirmations >= min_confirmations:
                balance += utxo.amount
        
        return balance
    
    def get_unconfirmed_balance(self, address: str) -> int:
        """Get unconfirmed balance (0 confirmations)"""
        if address not in self.utxos:
            return 0
        
        balance = 0
        for utxo in self.utxos[address]:
            if utxo.confirmations == 0:
                balance += utxo.amount
        
        return balance
    
    def get_total_balance(self, address: str) -> int:
        """Get total balance (confirmed + unconfirmed)"""
        return self.get_balance(address, 0)
    
    def get_utxos(self, address: str, min_confirmations: int = 1) -> List[UTXO]:
        """Get UTXOs for an address"""
        if address not in self.utxos:
            return []
        
        return [
            utxo for utxo in self.utxos[address]
            if utxo.confirmations >= min_confirmations
        ]
    
    def select_utxos_for_amount(self, address: str, target_amount: int, 
                               min_confirmations: int = 1) -> Tuple[List[UTXO], int]:
        """
        Select UTXOs to spend for a target amount using coin selection algorithm
        
        Args:
            address: Address to spend from
            target_amount: Amount to spend in satoshis
            min_confirmations: Minimum confirmations required
            
        Returns:
            Tuple[List[UTXO], int]: (selected_utxos, total_amount)
        """
        available_utxos = self.get_utxos(address, min_confirmations)
        
        if not available_utxos:
            return [], 0
        
        # Sort UTXOs by amount (largest first for efficiency)
        available_utxos.sort(key=lambda x: x.amount, reverse=True)
        
        # Simple greedy selection
        selected = []
        total = 0
        
        for utxo in available_utxos:
            selected.append(utxo)
            total += utxo.amount
            
            if total >= target_amount:
                break
        
        return selected, total
    
    def calculate_transaction_fee(self, inputs: List[UTXO], outputs: List[Dict], 
                                fee_rate: int = 10) -> int:
        """
        Calculate transaction fee based on size
        
        Args:
            inputs: Input UTXOs
            outputs: Output specifications
            fee_rate: Fee rate in satoshis per byte
            
        Returns:
            int: Estimated fee in satoshis
        """
        # Estimate transaction size
        # Base size: 10 bytes (version, input count, output count, locktime)
        base_size = 10
        
        # Input size: 148 bytes per input (typical P2PKH)
        input_size = len(inputs) * 148
        
        # Output size: 34 bytes per output (typical P2PKH)
        output_size = len(outputs) * 34
        
        total_size = base_size + input_size + output_size
        
        return total_size * fee_rate
    
    def create_transaction(self, from_address: str, to_address: str, 
                          amount: int, fee_rate: int = 10) -> Optional[Dict]:
        """
        Create a transaction spending from one address to another
        
        Args:
            from_address: Source address
            to_address: Destination address
            amount: Amount to send in satoshis
            fee_rate: Fee rate in satoshis per byte
            
        Returns:
            Optional[Dict]: Transaction data or None if insufficient funds
        """
        # Select UTXOs
        selected_utxos, total_input = self.select_utxos_for_amount(from_address, amount)
        
        if total_input < amount:
            return None  # Insufficient funds
        
        # Create outputs
        outputs = [{'address': to_address, 'amount': amount}]
        
        # Calculate fee
        fee = self.calculate_transaction_fee(selected_utxos, outputs, fee_rate)
        
        # Check if we have enough for fee
        if total_input < amount + fee:
            # Try to select more UTXOs
            selected_utxos, total_input = self.select_utxos_for_amount(
                from_address, amount + fee
            )
            if total_input < amount + fee:
                return None  # Still insufficient funds
        
        # Add change output if necessary
        change = total_input - amount - fee
        if change > 546:  # Dust threshold
            outputs.append({'address': from_address, 'amount': change})
        
        # Create transaction structure
        transaction = {
            'inputs': [
                {
                    'prev_txid': utxo.txid,
                    'prev_vout': utxo.vout,
                    'address': utxo.address,
                    'amount': utxo.amount,
                    'script_pubkey': utxo.script_pubkey.hex()
                }
                for utxo in selected_utxos
            ],
            'outputs': outputs,
            'fee': fee,
            'total_input': total_input,
            'total_output': sum(out['amount'] for out in outputs)
        }
        
        return transaction
    
    def get_transaction_history(self, address: str, limit: int = 50) -> List[Dict]:
        """
        Get transaction history for an address
        
        Args:
            address: Address to get history for
            limit: Maximum number of transactions
            
        Returns:
            List[Dict]: Transaction history
        """
        if address not in self.address_history:
            return []
        
        history = []
        txids = self.address_history[address][-limit:]  # Get latest transactions
        
        for txid in reversed(txids):  # Most recent first
            if txid in self.transactions:
                tx = self.transactions[txid]
                
                # Calculate net amount for this address
                net_amount = 0
                tx_type = 'unknown'
                
                # Check inputs
                for inp in tx.inputs:
                    if inp.get('address') == address:
                        net_amount -= inp.get('amount', 0)
                        tx_type = 'sent'
                
                # Check outputs
                for out in tx.outputs:
                    if out.get('address') == address:
                        net_amount += out.get('amount', 0)
                        if tx_type != 'sent':
                            tx_type = 'received'
                
                history.append({
                    'txid': txid,
                    'type': tx_type,
                    'amount': abs(net_amount),
                    'net_amount': net_amount,
                    'confirmations': tx.confirmations,
                    'timestamp': tx.timestamp,
                    'block_height': tx.block_height,
                    'fee': tx.fee if tx_type == 'sent' else 0
                })
        
        return history
    
    def get_address_stats(self, address: str) -> Dict:
        """Get comprehensive statistics for an address"""
        balance = self.get_balance(address)
        unconfirmed = self.get_unconfirmed_balance(address)
        utxos = self.get_utxos(address, 0)
        history = self.get_transaction_history(address)
        
        # Calculate statistics
        total_received = sum(
            tx['amount'] for tx in history if tx['type'] == 'received'
        )
        total_sent = sum(
            tx['amount'] for tx in history if tx['type'] == 'sent'
        )
        total_fees = sum(
            tx['fee'] for tx in history if tx['type'] == 'sent'
        )
        
        return {
            'address': address,
            'balance': balance,
            'unconfirmed_balance': unconfirmed,
            'total_balance': balance + unconfirmed,
            'utxo_count': len(utxos),
            'transaction_count': len(history),
            'total_received': total_received,
            'total_sent': total_sent,
            'total_fees': total_fees,
            'first_seen': min((tx['timestamp'] for tx in history), default=0),
            'last_seen': max((tx['timestamp'] for tx in history), default=0)
        }


class EthereumBalanceCalculator:
    """Balance calculator for Ethereum (account-based model)"""
    
    def __init__(self):
        self.balances: Dict[str, int] = {}  # address -> balance in wei
        self.nonces: Dict[str, int] = {}    # address -> nonce
        self.transactions: Dict[str, Dict] = {}  # txid -> transaction
        self.address_history: Dict[str, List[str]] = {}  # address -> txid list
    
    def add_transaction(self, tx_data: Dict):
        """Add Ethereum transaction"""
        txid = tx_data['hash']
        self.transactions[txid] = tx_data
        
        from_addr = tx_data.get('from', '').lower()
        to_addr = tx_data.get('to', '').lower()
        value = tx_data.get('value', 0)
        gas_used = tx_data.get('gas_used', 0)
        gas_price = tx_data.get('gas_price', 0)
        
        # Update balances
        if from_addr:
            if from_addr not in self.balances:
                self.balances[from_addr] = 0
            
            # Subtract value and gas fee
            self.balances[from_addr] -= value + (gas_used * gas_price)
            
            # Update nonce
            self.nonces[from_addr] = tx_data.get('nonce', 0) + 1
            
            # Update history
            if from_addr not in self.address_history:
                self.address_history[from_addr] = []
            self.address_history[from_addr].append(txid)
        
        if to_addr and to_addr != from_addr:
            if to_addr not in self.balances:
                self.balances[to_addr] = 0
            
            # Add received value
            self.balances[to_addr] += value
            
            # Update history
            if to_addr not in self.address_history:
                self.address_history[to_addr] = []
            self.address_history[to_addr].append(txid)
    
    def get_balance(self, address: str) -> int:
        """Get balance in wei"""
        return self.balances.get(address.lower(), 0)
    
    def get_balance_eth(self, address: str) -> float:
        """Get balance in ETH"""
        return self.get_balance(address) / 1e18
    
    def get_nonce(self, address: str) -> int:
        """Get current nonce for address"""
        return self.nonces.get(address.lower(), 0)


def demo_balance_calculation():
    """Demonstrate balance calculation algorithms"""
    print("=== Balance Calculation Demo ===\n")
    
    # Create balance calculator
    calc = BalanceCalculator()
    
    # Test addresses
    address1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    address2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    
    print("1. Adding Sample Transactions:")
    
    # Transaction 1: Coinbase (mining reward)
    tx1 = Transaction(
        txid="tx1_coinbase",
        inputs=[],  # Coinbase has no inputs
        outputs=[{
            'address': address1,
            'amount': 5000000000,  # 50 BTC
            'script_pubkey': '76a914' + '0' * 40 + '88ac'
        }],
        block_height=1,
        timestamp=1231006505,
        confirmations=100,
        fee=0
    )
    calc.add_transaction(tx1)
    
    # Transaction 2: Transfer from address1 to address2
    tx2 = Transaction(
        txid="tx2_transfer",
        inputs=[{
            'prev_txid': 'tx1_coinbase',
            'prev_vout': 0,
            'address': address1,
            'amount': 5000000000
        }],
        outputs=[
            {
                'address': address2,
                'amount': 3000000000,  # 30 BTC
                'script_pubkey': '76a914' + '1' * 40 + '88ac'
            },
            {
                'address': address1,  # Change
                'amount': 1999990000,  # 19.9999 BTC (minus fee)
                'script_pubkey': '76a914' + '0' * 40 + '88ac'
            }
        ],
        block_height=2,
        timestamp=1231006600,
        confirmations=99,
        fee=10000  # 0.0001 BTC fee
    )
    calc.add_transaction(tx2)
    
    print(f"Added transaction 1: Coinbase -> {address1}")
    print(f"Added transaction 2: {address1} -> {address2}")
    
    # Check balances
    print("\n2. Balance Information:")
    balance1 = calc.get_balance(address1)
    balance2 = calc.get_balance(address2)
    
    print(f"{address1}: {balance1:,} satoshis ({balance1/1e8:.8f} BTC)")
    print(f"{address2}: {balance2:,} satoshis ({balance2/1e8:.8f} BTC)")
    
    # Get UTXOs
    print("\n3. UTXO Information:")
    utxos1 = calc.get_utxos(address1)
    utxos2 = calc.get_utxos(address2)
    
    print(f"{address1} UTXOs: {len(utxos1)}")
    for utxo in utxos1:
        print(f"  {utxo.txid}:{utxo.vout} - {utxo.amount:,} satoshis")
    
    print(f"{address2} UTXOs: {len(utxos2)}")
    for utxo in utxos2:
        print(f"  {utxo.txid}:{utxo.vout} - {utxo.amount:,} satoshis")
    
    # Test coin selection
    print("\n4. Coin Selection Test:")
    target_amount = 1000000000  # 10 BTC
    selected, total = calc.select_utxos_for_amount(address1, target_amount)
    
    print(f"Target amount: {target_amount:,} satoshis")
    print(f"Selected UTXOs: {len(selected)}")
    print(f"Total selected: {total:,} satoshis")
    
    # Create transaction
    print("\n5. Transaction Creation:")
    new_tx = calc.create_transaction(address1, address2, 500000000, fee_rate=10)
    
    if new_tx:
        print("Transaction created successfully:")
        print(f"  Inputs: {len(new_tx['inputs'])}")
        print(f"  Outputs: {len(new_tx['outputs'])}")
        print(f"  Fee: {new_tx['fee']:,} satoshis")
        print(f"  Total input: {new_tx['total_input']:,} satoshis")
        print(f"  Total output: {new_tx['total_output']:,} satoshis")
    else:
        print("Transaction creation failed (insufficient funds)")
    
    # Transaction history
    print("\n6. Transaction History:")
    history1 = calc.get_transaction_history(address1)
    history2 = calc.get_transaction_history(address2)
    
    print(f"{address1} history ({len(history1)} transactions):")
    for tx in history1:
        print(f"  {tx['txid']}: {tx['type']} {tx['net_amount']:,} satoshis")
    
    print(f"{address2} history ({len(history2)} transactions):")
    for tx in history2:
        print(f"  {tx['txid']}: {tx['type']} {tx['net_amount']:,} satoshis")
    
    # Address statistics
    print("\n7. Address Statistics:")
    stats1 = calc.get_address_stats(address1)
    stats2 = calc.get_address_stats(address2)
    
    print(f"{address1} stats:")
    for key, value in stats1.items():
        if key != 'address':
            print(f"  {key}: {value:,}")
    
    print(f"{address2} stats:")
    for key, value in stats2.items():
        if key != 'address':
            print(f"  {key}: {value:,}")
    
    # Ethereum balance calculation
    print("\n8. Ethereum Balance Calculation:")
    eth_calc = EthereumBalanceCalculator()
    
    eth_addr1 = "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6"
    eth_addr2 = "0x8ba1f109551bD432803012645Hac136c5C1515BC"
    
    # Add Ethereum transaction
    eth_tx = {
        'hash': '0x1234567890abcdef',
        'from': eth_addr1,
        'to': eth_addr2,
        'value': 1000000000000000000,  # 1 ETH in wei
        'gas_used': 21000,
        'gas_price': 20000000000,  # 20 Gwei
        'nonce': 0,
        'block_number': 12345678
    }
    
    # Set initial balance
    eth_calc.balances[eth_addr1.lower()] = 5000000000000000000  # 5 ETH
    
    eth_calc.add_transaction(eth_tx)
    
    print(f"{eth_addr1}: {eth_calc.get_balance_eth(eth_addr1):.6f} ETH")
    print(f"{eth_addr2}: {eth_calc.get_balance_eth(eth_addr2):.6f} ETH")
    print(f"{eth_addr1} nonce: {eth_calc.get_nonce(eth_addr1)}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_balance_calculation()