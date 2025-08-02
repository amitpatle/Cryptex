import React, { useState } from 'react';
import { X, Plus, Download } from 'lucide-react';
import { WalletService } from '../services/walletService';
import { Wallet } from '../types/wallet';

interface CreateWalletModalProps {
  isOpen: boolean;
  onClose: () => void;
  onWalletCreated: (wallet: Wallet) => void;
}

export const CreateWalletModal: React.FC<CreateWalletModalProps> = ({
  isOpen,
  onClose,
  onWalletCreated
}) => {
  const [walletName, setWalletName] = useState('');
  const [selectedCurrency, setSelectedCurrency] = useState('bitcoin');
  const [importMode, setImportMode] = useState(false);
  const [privateKey, setPrivateKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const currencies = [
    { value: 'bitcoin', label: 'Bitcoin (BTC)', icon: '₿' },
    { value: 'ethereum', label: 'Ethereum (ETH)', icon: 'Ξ' },
    { value: 'litecoin', label: 'Litecoin (LTC)', icon: 'Ł' }
  ];

  const handleCreateWallet = async () => {
    if (!walletName.trim()) return;

    setIsLoading(true);
    try {
      let wallet: Wallet | null = null;

      if (importMode) {
        if (!privateKey.trim()) {
          alert('Please enter a private key');
          return;
        }
        wallet = WalletService.importWallet(privateKey, selectedCurrency, walletName);
      } else {
        wallet = WalletService.generateWallet(selectedCurrency, walletName);
      }

      if (wallet) {
        onWalletCreated(wallet);
        resetForm();
        onClose();
      } else {
        alert('Failed to create/import wallet');
      }
    } catch (error) {
      console.error('Error creating wallet:', error);
      alert('Failed to create wallet');
    } finally {
      setIsLoading(false);
    }
  };

  const resetForm = () => {
    setWalletName('');
    setSelectedCurrency('bitcoin');
    setImportMode(false);
    setPrivateKey('');
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800">
            {importMode ? 'Import Wallet' : 'Create New Wallet'}
          </h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-full transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div className="flex space-x-2 mb-4">
            <button
              onClick={() => setImportMode(false)}
              className={`flex-1 py-2 px-4 rounded-lg font-medium transition-colors ${
                !importMode 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              <Plus className="w-4 h-4 inline mr-2" />
              Create
            </button>
            <button
              onClick={() => setImportMode(true)}
              className={`flex-1 py-2 px-4 rounded-lg font-medium transition-colors ${
                importMode 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              <Download className="w-4 h-4 inline mr-2" />
              Import
            </button>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Wallet Name
            </label>
            <input
              type="text"
              value={walletName}
              onChange={(e) => setWalletName(e.target.value)}
              placeholder="Enter wallet name"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Currency
            </label>
            <select
              value={selectedCurrency}
              onChange={(e) => setSelectedCurrency(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              {currencies.map((currency) => (
                <option key={currency.value} value={currency.value}>
                  {currency.icon} {currency.label}
                </option>
              ))}
            </select>
          </div>

          {importMode && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Private Key
              </label>
              <textarea
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                placeholder="Enter your private key"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent h-24 resize-none"
              />
              <p className="text-xs text-gray-500 mt-1">
                Your private key is encrypted and stored locally on your device.
              </p>
            </div>
          )}

          <button
            onClick={handleCreateWallet}
            disabled={isLoading || !walletName.trim() || (importMode && !privateKey.trim())}
            className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 px-4 rounded-lg font-medium hover:from-blue-700 hover:to-purple-700 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? 'Processing...' : importMode ? 'Import Wallet' : 'Create Wallet'}
          </button>
        </div>
      </div>
    </div>
  );
};