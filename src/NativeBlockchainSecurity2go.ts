import { TurboModuleRegistry, type TurboModule } from 'react-native';

export type KeyInfoResult = {
  publicKeyHex: string;
  globalSigCounter: number;
  sigCounter: number;
};

export type SignatureResult = {
  signatureHex: string;
  globalSigCounter: number;
  sigCounter: number;
};

export interface Spec extends TurboModule {
  /** Whether this device has NFC hardware capable of reading ISO7816 tags. */
  isNfcSupported(): Promise<boolean>;

  /**
   * Starts an NFC reader session and waits for a Blockchain Security2Go card
   * to be tapped. Resolves once a card is connected and ready to exchange
   * APDUs. `alertMessage` is shown in the iOS system NFC sheet.
   */
  startSession(alertMessage: string): Promise<void>;

  /** Ends the current NFC reader session, if any. */
  stopSession(): Promise<void>;

  /** Sends a raw APDU (as hex) to the connected card and returns the raw response (as hex, status word included). */
  transceive(apduHex: string): Promise<string>;

  /** Sends SELECT_APPLICATION for the Blockchain Security2Go applet. */
  selectApplication(): Promise<boolean>;

  /** Reads the public key + signature counters stored at `keyIndex` (0 = default key). */
  getKeyInfo(keyIndex: number): Promise<KeyInfoResult>;

  /** Generates a new keypair on the given curve (0 = secp256k1) and returns its key index. */
  generateKeyPair(curveIndex: number): Promise<number>;

  /** Derives a new keypair from externally supplied seed bytes (hex). */
  generateKeyFromSeed(seedHex: string): Promise<void>;

  /**
   * Convenience wrapper mirroring the reference apps: selects the applet,
   * reads the key at `keyIndex`, generating new keys on the card as needed
   * until that index exists.
   */
  getOrCreateKey(keyIndex: number, curveIndex: number): Promise<KeyInfoResult>;

  /** Signs a pre-hashed digest (hex) with the key at `keyIndex`. */
  generateSignature(
    keyIndex: number,
    hashHex: string
  ): Promise<SignatureResult>;

  /** Sets the card PIN for the first time (hex-encoded PIN bytes). */
  setPin(pinHex: string): Promise<void>;

  /** Verifies the card PIN (hex-encoded PIN bytes). */
  verifyPin(pinHex: string): Promise<void>;

  /** Unlocks the card using the PUK after too many failed PIN attempts (hex-encoded PUK bytes). */
  unlockPin(pukHex: string): Promise<void>;

  /** Changes the card PIN (hex-encoded current/new PIN bytes). */
  changePin(currentPinHex: string, newPinHex: string): Promise<void>;

  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

export default TurboModuleRegistry.getEnforcing<Spec>('BlockchainSecurity2go');
