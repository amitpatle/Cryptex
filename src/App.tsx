import React, { useState, useEffect } from 'react';
import { Plus, Wallet as WalletIcon, Send, RefreshCw, TrendingUp } from 'lucide-react';
import { WalletCard } from './components/WalletCard';
import { CreateWalletModal } from './components/CreateWalletModal';
import { SendModal } from './components/SendModal';
import { TransactionHistory } from './components/TransactionHistory';
import { Wallet, Transaction, CryptoPrice } from './types/wallet';
import { WalletService } from './services/walletService';
import { CryptoApiService } from './services/cryptoApi';

function App() {
  const [wallets, setWallets] = useState<Wallet[]>([]);
  const [selectedWallet, setSelectedWallet] = useState<Wallet | null>(null);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [prices, setPrices] = useState<{ [key: string]: CryptoPrice }>({});
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isSendModalOpen, setIsSendModalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Load wallets on component mount
  useEffect(() => {
    const savedWallets = WalletService.loadWallets();
    setWallets(savedWallets);
    
    if (savedWallets.length > 0) {
      setSelectedWallet(savedWallets[0]);
    }
  }, []);

  // Load prices and balances
  useEffect(() => {
    if (wallets.length > 0) {
      loadPricesAndBalances();
    }
  }, [wallets]);

  // Load transaction history for selected wallet
  useEffect(() => {
    if (selectedWallet) {
      loadTransactionHistory();
    }
  }, [selectedWallet]);

  const loadPricesAndBalances = async () => {
    setIsLoading(true);
    try {
      // Get unique currencies
      const currencies = [...new Set(wallets.map(w => w.currency))];
      
      // Load prices
      const priceResult = await CryptoApiService.getPrices(currencies);
      if (priceResult.success && priceResult.data) {
        const priceMap: { [key: string]: CryptoPrice } = {};
        priceResult.data.forEach(price => {
          priceMap[price.symbol] = price;
        });
        setPrices(priceMap);
      }

      // Update wallet balances
      const updatedWallets = await Promise.all(
        wallets.map(async (wallet) => {
          let balanceResult;
          
          switch (wallet.currency.toUpperCase()) {
            case 'BITCOIN':
            case 'BTC':
              balanceResult = await CryptoApiService.getBitcoinBalance(wallet.address);
              break;
            case 'ETHEREUM':
            case 'ETH':
              balanceResult = await CryptoApiService.getEthereumBalance(wallet.address);
              break;
            default:
              // For other currencies, use a mock balance
              balanceResult = { success: true, data: Math.random() * 5 + 0.1 };
          }

          if (balanceResult.success && balanceResult.data !== undefined) {
            return { ...wallet, balance: balanceResult.data };
          }
          return wallet;
        })
      );

      setWallets(updatedWallets);
      WalletService.saveWallets(updatedWallets);

      // Update selected wallet if it exists
      if (selectedWallet) {
        const updatedSelected = updatedWallets.find(w => w.id === selectedWallet.id);
        if (updatedSelected) {
          setSelectedWallet(updatedSelected);
        }
      }
    } catch (error) {
      console.error('Error loading prices and balances:', error);
      // Show user-friendly error message
      console.warn('Using offline mode with mock data');
    } finally {
      setIsLoading(false);
    }
  };

  const loadTransactionHistory = async () => {
    if (!selectedWallet) return;

    try {
      const result = await CryptoApiService.getTransactionHistory(
        selectedWallet.address,
        selectedWallet.currency
      );
      
      if (result.success && result.data) {
        setTransactions(result.data);
      }
    } catch (error) {
      console.error('Error loading transaction history:', error);
    }
  };

  const handleCreateWallet = (newWallet: Wallet) => {
    const updatedWallets = [...wallets, newWallet];
    setWallets(updatedWallets);
    WalletService.saveWallets(updatedWallets);
    
    if (!selectedWallet) {
      setSelectedWallet(newWallet);
    }
  };

  const handleTransactionSent = () => {
    // Refresh balances and transaction history
    loadPricesAndBalances();
    loadTransactionHistory();
  };

  const getTotalPortfolioValue = () => {
    return wallets.reduce((total, wallet) => {
      const price = prices[wallet.currency]?.price || 0;
      return total + (wallet.balance * price);
    }, 0);
  };

  const getPortfolioChange = () => {
    const totalChange = wallets.reduce((total, wallet) => {
      const price = prices[wallet.currency];
      if (!price) return total;
      const value = wallet.balance * price.price;
      const change = (value * price.change24h) / 100;
      return total + change;
    }, 0);

    const totalValue = getTotalPortfolioValue();
    return totalValue > 0 ? (totalChange / totalValue) * 100 : 0;
  };

  const portfolioValue = getTotalPortfolioValue();
  const portfolioChange = getPortfolioChange();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center space-x-3">
            <div className="bg-gradient-to-br from-blue-600 to-purple-600 p-3 rounded-2xl">
              <WalletIcon className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-gray-800">CryptoWallet</h1>
              <p className="text-gray-600">Secure multi-currency wallet</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={loadPricesAndBalances}
              disabled={isLoading}
              className="p-3 bg-white/80 backdrop-blur-lg rounded-xl shadow-lg border border-white/20 hover:bg-white/90 transition-all duration-200 disabled:opacity-50"
            >
              <RefreshCw className={`w-5 h-5 text-gray-600 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="flex items-center space-x-2 bg-gradient-to-r from-blue-600 to-purple-600 text-white px-6 py-3 rounded-xl font-medium hover:from-blue-700 hover:to-purple-700 transition-all duration-200 shadow-lg"
            >
              <Plus className="w-5 h-5" />
              <span>Add Wallet</span>
            </button>
          </div>
        </div>

        {/* Portfolio Overview */}
        <div className="bg-white/80 backdrop-blur-lg rounded-2xl p-8 shadow-xl border border-white/20 mb-8">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-2xl font-bold text-gray-800 mb-2">Portfolio Overview</h2>
              <div className="flex items-center space-x-4">
                <div>
                  <p className="text-4xl font-bold text-gray-800">
                    ${portfolioValue.toFixed(2)}
                  </p>
                  <div className="flex items-center space-x-2 mt-1">
                    <TrendingUp className={`w-4 h-4 ${portfolioChange >= 0 ? 'text-green-600' : 'text-red-600'}`} />
                    <span className={`text-sm font-medium ${portfolioChange >= 0 ? 'text-green-600' : 'text-red-600'}`}>
                      {portfolioChange >= 0 ? '+' : ''}{portfolioChange.toFixed(2)}% (24h)
                    </span>
                  </div>
                </div>
              </div>
            </div>
            
            {selectedWallet && (
              <button
                onClick={() => setIsSendModalOpen(true)}
                className="flex items-center space-x-2 bg-gradient-to-r from-green-600 to-blue-600 text-white px-6 py-3 rounded-xl font-medium hover:from-green-700 hover:to-blue-700 transition-all duration-200 shadow-lg"
              >
                <Send className="w-5 h-5" />
                <span>Send</span>
              </button>
            )}
          </div>
        </div>

        {/* Wallets Grid */}
        {wallets.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            {wallets.map((wallet) => {
              const price = prices[wallet.currency]?.price || 0;
              const change24h = prices[wallet.currency]?.change24h || 0;
              
              return (
                <WalletCard
                  key={wallet.id}
                  wallet={wallet}
                  price={price}
                  change24h={change24h}
                  onClick={() => setSelectedWallet(wallet)}
                />
              );
            })}
          </div>
        ) : (
          <div className="bg-white/80 backdrop-blur-lg rounded-2xl p-12 shadow-xl border border-white/20 text-center mb-8">
            <div className="text-gray-400 mb-6">
              <WalletIcon className="w-16 h-16 mx-auto" />
            </div>
            <h3 className="text-2xl font-semibold text-gray-600 mb-4">No wallets yet</h3>
            <p className="text-gray-500 mb-6">Create your first wallet to get started with cryptocurrency management</p>
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="bg-gradient-to-r from-blue-600 to-purple-600 text-white px-8 py-4 rounded-xl font-medium hover:from-blue-700 hover:to-purple-700 transition-all duration-200 shadow-lg"
            >
              Create Your First Wallet
            </button>
          </div>
        )}

        {/* Transaction History */}
        {selectedWallet && (
          <TransactionHistory 
            transactions={transactions} 
            walletAddress={selectedWallet.address}
          />
        )}

        {/* Modals */}
        <CreateWalletModal
          isOpen={isCreateModalOpen}
          onClose={() => setIsCreateModalOpen(false)}
          onWalletCreated={handleCreateWallet}
        />

        {selectedWallet && (
          <SendModal
            isOpen={isSendModalOpen}
            onClose={() => setIsSendModalOpen(false)}
            wallet={selectedWallet}
            onTransactionSent={handleTransactionSent}
          />
        )}
      </div>
    </div>
  );
}

export default App;