import React, { useState } from 'react';
import { X, Send, AlertTriangle } from 'lucide-react';
import { Wallet } from '../types/wallet';
import { CryptoApiService } from '../services/cryptoApi';

interface SendModalProps {
  isOpen: boolean;
  onClose: () => void;
  wallet: Wallet;
  onTransactionSent: () => void;
}

export const SendModal: React.FC<SendModalProps> = ({
  isOpen,
  onClose,
  wallet,
  onTransactionSent
}) => {
  const [toAddress, setToAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});

  const validateForm = () => {
    const newErrors: { [key: string]: string } = {};

    if (!toAddress.trim()) {
      newErrors.toAddress = 'Recipient address is required';
    } else if (toAddress.length < 25) {
      newErrors.toAddress = 'Invalid address format';
    }

    if (!amount.trim()) {
      newErrors.amount = 'Amount is required';
    } else {
      const amountNum = parseFloat(amount);
      if (isNaN(amountNum) || amountNum <= 0) {
        newErrors.amount = 'Amount must be greater than 0';
      } else if (amountNum > wallet.balance) {
        newErrors.amount = 'Insufficient balance';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSend = async () => {
    if (!validateForm()) return;

    setIsLoading(true);
    try {
      const result = await CryptoApiService.sendTransaction(
        wallet.address,
        toAddress.trim(),
        parseFloat(amount),
        wallet.currency,
        wallet.privateKey
      );

      if (result.success) {
        alert(`Transaction sent successfully! Hash: ${result.data}`);
        onTransactionSent();
        resetForm();
        onClose();
      } else {
        alert(`Failed to send transaction: ${result.error}`);
      }
    } catch (error) {
      console.error('Error sending transaction:', error);
      alert('Failed to send transaction');
    } finally {
      setIsLoading(false);
    }
  };

  const resetForm = () => {
    setToAddress('');
    setAmount('');
    setErrors({});
  };

  const maxAmount = wallet.balance * 0.95; // Reserve 5% for fees

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800">Send {wallet.currency}</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-full transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-yellow-600 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-yellow-800">
              <p className="font-medium">Important</p>
              <p>Double-check the recipient address. Transactions cannot be reversed.</p>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              From Wallet
            </label>
            <div className="bg-gray-50 rounded-lg p-3">
              <p className="font-medium text-gray-800">{wallet.name}</p>
              <p className="text-sm text-gray-600">
                Balance: {wallet.balance.toFixed(6)} {wallet.currency}
              </p>
              <p className="text-xs text-gray-400 truncate">{wallet.address}</p>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Recipient Address
            </label>
            <input
              type="text"
              value={toAddress}
              onChange={(e) => setToAddress(e.target.value)}
              placeholder="Enter recipient address"
              className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                errors.toAddress ? 'border-red-300' : 'border-gray-300'
              }`}
            />
            {errors.toAddress && (
              <p className="text-sm text-red-600 mt-1">{errors.toAddress}</p>
            )}
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-gray-700">
                Amount ({wallet.currency})
              </label>
              <button
                onClick={() => setAmount(maxAmount.toString())}
                className="text-sm text-blue-600 hover:text-blue-700 font-medium"
              >
                Max
              </button>
            </div>
            <input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="0.00"
              step="0.000001"
              className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                errors.amount ? 'border-red-300' : 'border-gray-300'
              }`}
            />
            {errors.amount && (
              <p className="text-sm text-red-600 mt-1">{errors.amount}</p>
            )}
          </div>

          <div className="bg-gray-50 rounded-lg p-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Estimated Fee:</span>
              <span className="text-gray-800">~0.001 {wallet.currency}</span>
            </div>
            <div className="flex justify-between text-sm mt-1">
              <span className="text-gray-600">Total:</span>
              <span className="font-medium text-gray-800">
                {amount ? (parseFloat(amount) + 0.001).toFixed(6) : '0.001'} {wallet.currency}
              </span>
            </div>
          </div>

          <button
            onClick={handleSend}
            disabled={isLoading || !toAddress.trim() || !amount.trim()}
            className="w-full bg-gradient-to-r from-green-600 to-blue-600 text-white py-3 px-4 rounded-lg font-medium hover:from-green-700 hover:to-blue-700 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
          >
            <Send className="w-4 h-4" />
            <span>{isLoading ? 'Sending...' : 'Send Transaction'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};