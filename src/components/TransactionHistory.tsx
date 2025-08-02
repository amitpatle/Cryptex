import React from 'react';
import { Transaction } from '../types/wallet';
import { ArrowUpRight, ArrowDownLeft, Clock, CheckCircle, XCircle } from 'lucide-react';

interface TransactionHistoryProps {
  transactions: Transaction[];
  walletAddress: string;
}

export const TransactionHistory: React.FC<TransactionHistoryProps> = ({
  transactions,
  walletAddress
}) => {
  const getTransactionIcon = (transaction: Transaction) => {
    const isSent = transaction.from.toLowerCase() === walletAddress.toLowerCase();
    
    if (transaction.status === 'pending') {
      return <Clock className="w-5 h-5 text-yellow-500" />;
    } else if (transaction.status === 'failed') {
      return <XCircle className="w-5 h-5 text-red-500" />;
    } else if (isSent) {
      return <ArrowUpRight className="w-5 h-5 text-red-500" />;
    } else {
      return <ArrowDownLeft className="w-5 h-5 text-green-500" />;
    }
  };

  const getTransactionType = (transaction: Transaction) => {
    const isSent = transaction.from.toLowerCase() === walletAddress.toLowerCase();
    return isSent ? 'Sent' : 'Received';
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const truncateAddress = (address: string) => {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  if (transactions.length === 0) {
    return (
      <div className="bg-white/80 backdrop-blur-lg rounded-2xl p-8 shadow-xl border border-white/20 text-center">
        <div className="text-gray-400 mb-4">
          <Clock className="w-12 h-12 mx-auto" />
        </div>
        <h3 className="text-lg font-medium text-gray-600 mb-2">No transactions yet</h3>
        <p className="text-gray-500">Your transaction history will appear here</p>
      </div>
    );
  }

  return (
    <div className="bg-white/80 backdrop-blur-lg rounded-2xl shadow-xl border border-white/20 overflow-hidden">
      <div className="p-6 border-b border-gray-200">
        <h3 className="text-lg font-semibold text-gray-800">Transaction History</h3>
      </div>
      
      <div className="max-h-96 overflow-y-auto">
        {transactions.map((transaction) => {
          const isSent = transaction.from.toLowerCase() === walletAddress.toLowerCase();
          const otherAddress = isSent ? transaction.to : transaction.from;
          
          return (
            <div key={transaction.id} className="p-4 border-b border-gray-100 hover:bg-gray-50/50 transition-colors">
              <div className="flex items-center space-x-4">
                <div className="flex-shrink-0">
                  {getTransactionIcon(transaction)}
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="font-medium text-gray-800">
                        {getTransactionType(transaction)}
                      </p>
                      <p className="text-sm text-gray-500">
                        {isSent ? 'To' : 'From'}: {truncateAddress(otherAddress)}
                      </p>
                    </div>
                    
                    <div className="text-right">
                      <p className={`font-medium ${isSent ? 'text-red-600' : 'text-green-600'}`}>
                        {isSent ? '-' : '+'}{transaction.amount.toFixed(6)} {transaction.currency}
                      </p>
                      <p className="text-sm text-gray-500">
                        {formatDate(transaction.timestamp)}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between mt-2">
                    <div className="flex items-center space-x-2">
                      {transaction.status === 'confirmed' && (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      )}
                      <span className={`text-xs px-2 py-1 rounded-full ${
                        transaction.status === 'confirmed' 
                          ? 'bg-green-100 text-green-800'
                          : transaction.status === 'pending'
                          ? 'bg-yellow-100 text-yellow-800'
                          : 'bg-red-100 text-red-800'
                      }`}>
                        {transaction.status.charAt(0).toUpperCase() + transaction.status.slice(1)}
                      </span>
                    </div>
                    
                    <p className="text-xs text-gray-400">
                      Fee: {transaction.fee} {transaction.currency}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};