import React from 'react';
import { Wallet } from '../types/wallet';
import { Bitcoin, DollarSign, TrendingUp, TrendingDown } from 'lucide-react';

interface WalletCardProps {
  wallet: Wallet;
  price: number;
  change24h: number;
  onClick: () => void;
}

export const WalletCard: React.FC<WalletCardProps> = ({ wallet, price, change24h, onClick }) => {
  const getCurrencyIcon = (currency: string) => {
    switch (currency.toLowerCase()) {
      case 'bitcoin':
      case 'btc':
        return <Bitcoin className="w-8 h-8 text-orange-500" />;
      case 'ethereum':
      case 'eth':
        return <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-blue-500 rounded-full flex items-center justify-center text-white font-bold text-sm">Ξ</div>;
      case 'litecoin':
      case 'ltc':
        return <div className="w-8 h-8 bg-gradient-to-br from-gray-400 to-gray-600 rounded-full flex items-center justify-center text-white font-bold text-sm">Ł</div>;
      default:
        return <DollarSign className="w-8 h-8 text-green-500" />;
    }
  };

  const usdValue = wallet.balance * price;
  const isPositiveChange = change24h >= 0;

  return (
    <div 
      onClick={onClick}
      className="bg-white/80 backdrop-blur-lg rounded-2xl p-6 shadow-xl border border-white/20 hover:bg-white/90 transition-all duration-300 cursor-pointer transform hover:scale-105"
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-3">
          {getCurrencyIcon(wallet.currency)}
          <div>
            <h3 className="font-semibold text-gray-800">{wallet.name}</h3>
            <p className="text-sm text-gray-500">{wallet.currency}</p>
          </div>
        </div>
        <div className={`flex items-center space-x-1 ${isPositiveChange ? 'text-green-600' : 'text-red-600'}`}>
          {isPositiveChange ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />}
          <span className="text-sm font-medium">{change24h.toFixed(2)}%</span>
        </div>
      </div>

      <div className="space-y-2">
        <div>
          <p className="text-2xl font-bold text-gray-800">
            {wallet.balance.toFixed(6)} {wallet.currency}
          </p>
          <p className="text-lg text-gray-600">
            ${usdValue.toFixed(2)} USD
          </p>
        </div>
        
        <div className="pt-2">
          <p className="text-xs text-gray-400 truncate">
            {wallet.address}
          </p>
        </div>
      </div>
    </div>
  );
};