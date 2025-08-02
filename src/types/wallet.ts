export interface Wallet {
  id: string;
  name: string;
  address: string;
  privateKey: string;
  publicKey: string;
  currency: string;
  balance: number;
  usdValue: number;
}

export interface Transaction {
  id: string;
  hash: string;
  from: string;
  to: string;
  amount: number;
  currency: string;
  timestamp: number;
  status: 'pending' | 'confirmed' | 'failed';
  fee: number;
}

export interface CryptoPrice {
  symbol: string;
  price: number;
  change24h: number;
  marketCap: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}