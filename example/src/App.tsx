import { useCallback, useState } from 'react';
import {
  Button,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
} from 'react-native';
import {
  getOrCreateKey,
  isNfcSupported,
  startSession,
  stopSession,
} from 'react-native-blockchain-security2go';

export default function App() {
  const [log, setLog] = useState('');

  const readPublicKey = useCallback(async () => {
    try {
      if (!(await isNfcSupported())) {
        setLog('NFC is not supported on this device');
        return;
      }
      await startSession(
        'Hold your Blockchain Security2Go card near the device'
      );
      const key = await getOrCreateKey(/* keyIndex */ 1);
      setLog(`Public key: ${key.publicKeyHex}\nSig counter: ${key.sigCounter}`);
    } catch (error: any) {
      setLog(`Error: ${error?.code ?? ''} ${error?.message ?? error}`);
    } finally {
      await stopSession();
    }
  }, []);

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.content}>
        <Button title="Read public key from card" onPress={readPublicKey} />
        <Text style={styles.log}>{log}</Text>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  content: {
    flexGrow: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
    gap: 16,
  },
  log: {
    fontFamily: 'Courier',
  },
});
