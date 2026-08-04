import { NativeEventEmitter } from 'react-native';
import BlockchainSecurity2go, {
  type KeyInfoResult,
  type SignatureResult,
} from './NativeBlockchainSecurity2go';

export type { KeyInfoResult, SignatureResult };

export type NfcSessionEvent =
  | { type: 'tagDetected' }
  | { type: 'sessionInvalidated'; message?: string }
  | { type: 'error'; message: string };

// The TurboModule instance itself implements addListener/removeListeners,
// so it can be used directly as the emitter's native module.
const eventEmitter = new NativeEventEmitter(BlockchainSecurity2go as any);

const EVENT_NAME = 'BlockchainSecurity2goEvent';

/** Curve indices accepted by {@link generateKeyPair} / {@link getOrCreateKey}. */
export const Curve = {
  SECP256K1: 0,
} as const;

export function isNfcSupported(): Promise<boolean> {
  return BlockchainSecurity2go.isNfcSupported();
}

/**
 * Begins listening for an NFC tap. Resolves once a Blockchain Security2Go
 * card is connected. `alertMessage` is shown in the iOS system NFC sheet
 * while scanning (ignored on Android).
 */
export function startSession(
  alertMessage = 'Hold your card near the device'
): Promise<void> {
  return BlockchainSecurity2go.startSession(alertMessage);
}

export function stopSession(): Promise<void> {
  return BlockchainSecurity2go.stopSession();
}

/** Sends a raw APDU (hex-encoded) and returns the raw hex response, status word included. */
export function transceive(apduHex: string): Promise<string> {
  return BlockchainSecurity2go.transceive(apduHex);
}

export function selectApplication(): Promise<boolean> {
  return BlockchainSecurity2go.selectApplication();
}

export function getKeyInfo(keyIndex: number): Promise<KeyInfoResult> {
  return BlockchainSecurity2go.getKeyInfo(keyIndex);
}

export function generateKeyPair(
  curveIndex: number = Curve.SECP256K1
): Promise<number> {
  return BlockchainSecurity2go.generateKeyPair(curveIndex);
}

export function generateKeyFromSeed(seedHex: string): Promise<void> {
  return BlockchainSecurity2go.generateKeyFromSeed(seedHex);
}

export function getOrCreateKey(
  keyIndex: number,
  curveIndex: number = Curve.SECP256K1
): Promise<KeyInfoResult> {
  return BlockchainSecurity2go.getOrCreateKey(keyIndex, curveIndex);
}

export function generateSignature(
  keyIndex: number,
  hashHex: string
): Promise<SignatureResult> {
  return BlockchainSecurity2go.generateSignature(keyIndex, hashHex);
}

export function setPin(pinHex: string): Promise<void> {
  return BlockchainSecurity2go.setPin(pinHex);
}

export function verifyPin(pinHex: string): Promise<void> {
  return BlockchainSecurity2go.verifyPin(pinHex);
}

export function unlockPin(pukHex: string): Promise<void> {
  return BlockchainSecurity2go.unlockPin(pukHex);
}

export function changePin(
  currentPinHex: string,
  newPinHex: string
): Promise<void> {
  return BlockchainSecurity2go.changePin(currentPinHex, newPinHex);
}

/** Subscribes to NFC session lifecycle events (tag detected, session ended, errors). */
export function addNfcSessionListener(
  listener: (event: NfcSessionEvent) => void
) {
  return eventEmitter.addListener(
    EVENT_NAME,
    listener as (...args: readonly object[]) => void
  );
}
