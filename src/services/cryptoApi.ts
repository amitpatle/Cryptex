import axios from 'axios';
import { CryptoPrice, Transaction, ApiResponse } from '../types/wallet';

const COINGECKO_API = 'https://api.coingecko.com/api/v3';
const BLOCKCYPHER_API = 'https://api.blockcypher.com/v1';

export class CryptoApiService {
  // Get cryptocurrency prices
  static async getPrices(symbols: string[]): Promise<ApiResponse<CryptoPrice[]>> {
    try {
      const ids = symbols.map(s => s.toLowerCase()).join(',');
      const response = await axios.get(
        `${COINGECKO_API}/simple/price?ids=${ids}&vs_currencies=usd&include_24hr_change=true&include_market_cap=true`
      );
      
      const prices: CryptoPrice[] = Object.entries(response.data).map(([key, value]: [string, any]) => ({
        symbol: key.toUpperCase(),
        price: value.usd,
        change24h: value.usd_24h_change || 0,
        marketCap: value.usd_market_cap || 0
      }));

      return { success: true, data: prices };
    } catch (error) {
      return { success: false, error: 'Failed to fetch prices' };
    }
  }

  // Get Bitcoin balance
  static async getBitcoinBalance(address: string): Promise<ApiResponse<number>> {
    try {
      const response = await axios.get(`${BLOCKCYPHER_API}/btc/main/addrs/${address}/balance`);
      const balance = response.data.balance / 100000000; // Convert satoshis to BTC
      return { success: true, data: balance };
    } catch (error) {
      return { success: false, error: 'Failed to fetch Bitcoin balance' };
    }
  }

  // Get Ethereum balance (using public RPC)
  static async getEthereumBalance(address: string): Promise<ApiResponse<number>> {
    try {
      const response = await axios.post('https://eth-mainnet.public.blastapi.io', {
        jsonrpc: '2.0',
        method: 'eth_getBalance',
        params: [address, 'latest'],
        id: 1
      });

      if (response.data.result) {
        const balance = parseInt(response.data.result, 16) / 1e18; // Convert wei to ETH
        return { success: true, data: balance };
      }
      return { success: false, error: 'Invalid response' };
    } catch (error) {
      return { success: false, error: 'Failed to fetch Ethereum balance' };
    }
  }

  // Get transaction history (simplified for demo)
  static async getTransactionHistory(address: string, currency: string): Promise<ApiResponse<Transaction[]>> {
    try {
      // This is a simplified demo - in production, you'd use proper APIs
      const mockTransactions: Transaction[] = [
        {
          id: '1',
          hash: '0x1234...abcd',
          from: '0x5678...efgh',
          to: address,
          amount: 0.5,
          currency: currency.toUpperCase(),
          timestamp: Date.now() - 86400000,
          status: 'confirmed',
          fee: 0.001
        },
        {
          id: '2',
          hash: '0x5678...efgh',
          from: address,
          to: '0x9012...ijkl',
          amount: 0.2,
          currency: currency.toUpperCase(),
          timestamp: Date.now() - 172800000,
          status: 'confirmed',
          fee: 0.0015
        }
      ];

      return { success: true, data: mockTransactions };
    } catch (error) {
      return { success: false, error: 'Failed to fetch transaction history' };
    }
  }

  // Send transaction (simplified for demo)
  static async sendTransaction(
    fromAddress: string,
    toAddress: string,
    amount: number,
    currency: string,
    privateKey: string
  ): Promise<ApiResponse<string>> {
    try {
      // This is a demo implementation - in production, you'd use proper transaction signing
      const txHash = `0x${Math.random().toString(16).substr(2, 64)}`;
      return { success: true, data: txHash };
    } catch (error) {
      return { success: false, error: 'Failed to send transaction' };
    }
  }
}