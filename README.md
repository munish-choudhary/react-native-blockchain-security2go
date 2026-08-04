# react-native-blockchain-security2go

React Native wrapper for the [Infineon Blockchain Security2Go](https://www.infineon.com/) NFC secure element. It ports the ISO7816 APDU protocol implemented by Infineon/Coinfinity's reference [Android](https://github.com/Infineon/BlockchainSecurity2Go-Android) and [iOS](https://github.com/Infineon/BlockchainSecurity2Go-iOS) sample apps into a single TurboModule, so a React Native app can select the applet, read/generate keys, sign hashes, and manage the card PIN without writing any native code.

## Installation

```sh
npm install react-native-blockchain-security2go
```

### Android

No extra setup is required — the NFC permission is merged in automatically. Minimum SDK 24.

### iOS

NFC tag reading requires host app configuration that a library cannot inject for you:

1. In Xcode, select your app target → **Signing & Capabilities** → **+ Capability** → **Near Field Communication Tag Reading**. This adds `com.apple.developer.nfc.readersession.formats = [TAG]` to your entitlements file.
2. Add to your app's `Info.plist`:

   ```xml
   <key>NFCReaderUsageDescription</key>
   <string>Used to read your Blockchain Security2Go card</string>
   <key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
   <array>
     <string>D2760000041502000100000001</string>
   </array>
   ```

3. Run `pod install`. Requires a physical device — CoreNFC is unavailable in the Simulator.

## Usage

```ts
import {
  isNfcSupported,
  startSession,
  stopSession,
  getOrCreateKey,
  generateSignature,
} from 'react-native-blockchain-security2go';

async function readPublicKey() {
  if (!(await isNfcSupported())) {
    throw new Error('NFC not supported on this device');
  }

  await startSession('Hold your card near the device'); // resolves once a card is tapped
  try {
    const key = await getOrCreateKey(/* keyIndex */ 1); // generates the key on-card if missing
    console.log(key.publicKeyHex, key.globalSigCounter, key.sigCounter);
    return key;
  } finally {
    await stopSession();
  }
}

async function signHash(keyIndex: number, hashHex: string) {
  await startSession();
  try {
    return await generateSignature(keyIndex, hashHex); // { signatureHex, globalSigCounter, sigCounter }
  } finally {
    await stopSession();
  }
}
```

Every command (`selectApplication`, `getKeyInfo`, `generateKeyPair`, `generateKeyFromSeed`, `generateSignature`, `setPin`, `verifyPin`, `unlockPin`, `changePin`) must run between a `startSession()`/`stopSession()` pair — that's when the card is actually connected. `transceive(apduHex)` is available for sending raw APDUs directly if you need something outside this command set.

### Listening for session events

```ts
import { addNfcSessionListener } from 'react-native-blockchain-security2go';

const subscription = addNfcSessionListener((event) => {
  // event.type: 'tagDetected' | 'sessionInvalidated' | 'error'
  console.log(event);
});

// later
subscription.remove();
```

### Error codes

Rejected promises carry a `code` matching the card's ISO7816 status word or a local failure reason, so callers can branch without parsing messages:

| Code | Meaning |
| --- | --- |
| `SW_6A88` | No key exists at the requested index (thrown by `getKeyInfo`; `getOrCreateKey` handles this internally) |
| `SW_6A84` | Card's key storage is full |
| `SW_9000` / others | Raw status word echoed back for any other non-success response |
| `NO_ACTIVE_SESSION` | A command was called without an active `startSession()` |
| `NFC_NOT_SUPPORTED` | Device has no NFC reader |
| `IO_ERROR` | Card was moved away / NFC communication failure |
| `INVALID_RESPONSE` | Card returned malformed data for the command |
| `INVALID_ARGUMENT` | A hex string argument was malformed |

## API

| Function | Description |
| --- | --- |
| `isNfcSupported()` | Whether this device can read ISO7816 tags |
| `startSession(alertMessage?)` | Begin an NFC session; resolves once a card connects |
| `stopSession()` | End the current session |
| `selectApplication()` | Select the Blockchain Security2Go applet |
| `getKeyInfo(keyIndex)` | Read the public key + signature counters at `keyIndex` |
| `generateKeyPair(curveIndex?)` | Generate a new keypair (default: secp256k1); returns its index |
| `generateKeyFromSeed(seedHex)` | Derive a keypair from externally supplied seed bytes |
| `getOrCreateKey(keyIndex, curveIndex?)` | Select the applet, then read or generate the key at `keyIndex` |
| `generateSignature(keyIndex, hashHex)` | Sign a pre-hashed digest |
| `setPin(pinHex)` / `verifyPin(pinHex)` / `unlockPin(pukHex)` / `changePin(currentPinHex, newPinHex)` | PIN management |
| `transceive(apduHex)` | Send a raw APDU, get the raw hex response back (status word included) |
| `addNfcSessionListener(listener)` | Subscribe to `tagDetected` / `sessionInvalidated` / `error` events |

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
