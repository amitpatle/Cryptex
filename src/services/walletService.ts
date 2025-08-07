import CryptoJS from 'crypto-js';
import { Wallet } from '../types/wallet';

const STORAGE_KEY = 'crypto_wallets';

// Generate a more secure encryption key based on browser fingerprint
const generateEncryptionKey = (): string => {
  const fingerprint = [
    navigator.userAgent,
    navigator.language,
    screen.width,
    screen.height,
    new Date().getTimezoneOffset()
  ].join('|');
  
  return CryptoJS.SHA256(fingerprint + 'crypto_wallet_secret').toString();
};

const ENCRYPTION_KEY = generateEncryptionKey();

export class WalletService {
  // Generate a new wallet
  static generateWallet(currency: string, name: string): Wallet {
    const id = Date.now().toString();
    
    // Generate more secure keys
    const entropy = CryptoJS.lib.WordArray.random(32);
    const privateKey = entropy.toString();
    const publicKey = CryptoJS.SHA256(privateKey + Date.now()).toString();
    const address = this.generateAddress(publicKey, currency);

    return {
      id,
      name,
      address,
      privateKey,
      publicKey,
      currency: currency.toUpperCase(),
      balance: 0,
      usdValue: 0
    };
  }

  // Generate address from public key
  private static generateAddress(publicKey: string, currency: string): string {
    const hash = CryptoJS.SHA256(publicKey + currency).toString();
    
    switch (currency.toLowerCase()) {
      case 'bitcoin':
      case 'btc':
        return '1' + hash.substr(0, 33); // Simplified Bitcoin address
      case 'ethereum':
      case 'eth':
        return '0x' + hash.substr(0, 40); // Simplified Ethereum address
      case 'litecoin':
      case 'ltc':
        return 'L' + hash.substr(0, 33); // Simplified Litecoin address
      default:
        return '0x' + hash.substr(0, 40);
    }
  }

  // Save wallets to encrypted local storage
  static saveWallets(wallets: Wallet[]): boolean {
    try {
      const data = JSON.stringify(wallets);
      const encrypted = CryptoJS.AES.encrypt(data, ENCRYPTION_KEY).toString();
      localStorage.setItem(STORAGE_KEY, encrypted);
      return true;
    } catch (error) {
      console.error('Failed to save wallets:', error);
      return false;
    }
  }

  // Load wallets from encrypted local storage
  static loadWallets(): Wallet[] {
    try {
      const encrypted = localStorage.getItem(STORAGE_KEY);
      if (!encrypted) return [];

      const decrypted = CryptoJS.AES.decrypt(encrypted, ENCRYPTION_KEY);
      const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);
      
      if (!decryptedString) {
        console.warn('Failed to decrypt wallet data');
        return [];
      }
      
      return JSON.parse(decryptedString);
    } catch (error) {
      console.error('Failed to load wallets:', error);
      return [];
    }
  }

  // Import wallet from private key
  static importWallet(privateKey: string, currency: string, name: string): Wallet | null {
    try {
      if (!privateKey || privateKey.length < 32) {
        throw new Error('Invalid private key length');
      }
      
      const id = Date.now().toString();
      const publicKey = CryptoJS.SHA256(privateKey + 'public').toString();
      const address = this.generateAddress(publicKey, currency);

      return {
        id,
        name,
        address,
        privateKey,
        publicKey,
        currency: currency.toUpperCase(),
        balance: 0,
        usdValue: 0
      };
    } catch (error) {
      console.error('Failed to import wallet:', error);
      return null;
    }
  }

  // Validate wallet address format
  static validateAddress(address: string, currency: string): boolean {
    switch (currency.toLowerCase()) {
      case 'bitcoin':
      case 'btc':
        return /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address);
      case 'ethereum':
      case 'eth':
        return /^0x[a-fA-F0-9]{40}$/.test(address);
      case 'litecoin':
      case 'ltc':
        return /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/.test(address);
      default:
        return address.length > 20;
    }
  }
}