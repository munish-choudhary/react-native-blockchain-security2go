package com.blockchainsecurity2go

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule.RCTDeviceEventEmitter
import java.io.IOException

/**
 * Wraps the ISO7816 APDU protocol used by the Infineon Blockchain Security2Go
 * secure element, ported from the reference Android/iOS sample apps:
 * SELECT_APPLICATION -> GET_KEY_INFO / GENERATE_KEY / GENERATE_SIGNATURE /
 * SET_PIN / VERIFY_PIN / UNLOCK_PIN / CHANGE_PIN.
 */
class BlockchainSecurity2goModule(private val reactContext: ReactApplicationContext) :
  NativeBlockchainSecurity2goSpec(reactContext),
  NfcAdapter.ReaderCallback {

  private var currentIsoDep: IsoDep? = null
  private var startSessionPromise: Promise? = null

  override fun isNfcSupported(promise: Promise) {
    promise.resolve(NfcAdapter.getDefaultAdapter(reactContext) != null)
  }

  override fun startSession(alertMessage: String, promise: Promise) {
    val activity = reactContext.currentActivity
    if (activity == null) {
      promise.reject(CODE_NO_ACTIVITY, "No active Activity to start an NFC session")
      return
    }
    val nfcAdapter = NfcAdapter.getDefaultAdapter(activity)
    if (nfcAdapter == null) {
      promise.reject(CODE_NFC_NOT_SUPPORTED, "This device does not support NFC")
      return
    }

    closeCurrentTag()
    startSessionPromise = promise

    val options = Bundle()
    options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250)
    activity.runOnUiThread {
      nfcAdapter.enableReaderMode(
        activity,
        this,
        NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
        options
      )
    }
  }

  override fun stopSession(promise: Promise) {
    val activity = reactContext.currentActivity
    val nfcAdapter = activity?.let { NfcAdapter.getDefaultAdapter(it) }
    closeCurrentTag()
    startSessionPromise = null
    if (activity != null && nfcAdapter != null) {
      activity.runOnUiThread { nfcAdapter.disableReaderMode(activity) }
    }
    emitEvent(eventPayload("sessionInvalidated", null))
    promise.resolve(null)
  }

  override fun onTagDiscovered(tag: Tag) {
    val isoDep = IsoDep.get(tag)
    if (isoDep == null) {
      val error = "Detected tag does not support ISO7816 (IsoDep)"
      emitEvent(eventPayload("error", error))
      startSessionPromise?.reject(CODE_UNSUPPORTED_TAG, error)
      startSessionPromise = null
      return
    }
    try {
      isoDep.connect()
      isoDep.timeout = TRANSCEIVE_TIMEOUT_MS
      currentIsoDep = isoDep
      emitEvent(eventPayload("tagDetected", null))
      startSessionPromise?.resolve(null)
    } catch (e: IOException) {
      startSessionPromise?.reject(CODE_IO_ERROR, e.message, e)
    } finally {
      startSessionPromise = null
    }
  }

  override fun transceive(apduHex: String, promise: Promise) = executeCommand(promise) {
    val (data, sw) = transceiveApdu(hexToBytes(apduHex))
    promise.resolve(bytesToHex(data + swBytes(sw)))
  }

  override fun selectApplication(promise: Promise) = executeCommand(promise) {
    doSelectApplication()
    promise.resolve(true)
  }

  override fun getKeyInfo(keyIndex: Double, promise: Promise) = executeCommand(promise) {
    promise.resolve(doGetKeyInfo(keyIndex.toInt()))
  }

  override fun generateKeyPair(curveIndex: Double, promise: Promise) = executeCommand(promise) {
    promise.resolve(doGenerateKeyPair(curveIndex.toInt()).toDouble())
  }

  override fun generateKeyFromSeed(seedHex: String, promise: Promise) = executeCommand(promise) {
    val apdu = buildApdu(INS_GENERATE_KEY_FROM_SEED, 0x00, 0x00, hexToBytes(seedHex), leIncluded = false)
    val (_, sw) = transceiveApdu(apdu)
    ensureSuccess(sw)
    promise.resolve(null)
  }

  override fun getOrCreateKey(keyIndex: Double, curveIndex: Double, promise: Promise) =
    executeCommand(promise) {
      doSelectApplication()
      promise.resolve(doGetOrCreateKey(keyIndex.toInt(), curveIndex.toInt()))
    }

  override fun generateSignature(keyIndex: Double, hashHex: String, promise: Promise) =
    executeCommand(promise) {
      val apdu = buildApdu(INS_GENERATE_SIGNATURE, keyIndex.toInt(), 0x00, hexToBytes(hashHex), leIncluded = true)
      val (data, sw) = transceiveApdu(apdu)
      ensureSuccess(sw)
      if (data.size < 8) {
        throw ApduException(CODE_INVALID_RESPONSE, "GENERATE_SIGNATURE response too short")
      }
      val map = Arguments.createMap()
      map.putString("signatureHex", bytesToHex(data.copyOfRange(8, data.size)))
      map.putDouble("globalSigCounter", bytesToUnsignedLong(data.copyOfRange(0, 4)).toDouble())
      map.putDouble("sigCounter", bytesToUnsignedLong(data.copyOfRange(4, 8)).toDouble())
      promise.resolve(map)
    }

  override fun setPin(pinHex: String, promise: Promise) = executeCommand(promise) {
    val apdu = buildApdu(INS_SET_PIN, 0x00, 0x00, hexToBytes(pinHex), leIncluded = true)
    val (_, sw) = transceiveApdu(apdu)
    ensureSuccess(sw)
    promise.resolve(null)
  }

  override fun verifyPin(pinHex: String, promise: Promise) = executeCommand(promise) {
    val apdu = buildApdu(INS_VERIFY_PIN, 0x00, 0x00, hexToBytes(pinHex), leIncluded = false)
    val (_, sw) = transceiveApdu(apdu)
    ensureSuccess(sw)
    promise.resolve(null)
  }

  override fun unlockPin(pukHex: String, promise: Promise) = executeCommand(promise) {
    val apdu = buildApdu(INS_UNLOCK_PIN, 0x00, 0x00, hexToBytes(pukHex), leIncluded = false)
    val (_, sw) = transceiveApdu(apdu)
    ensureSuccess(sw)
    promise.resolve(null)
  }

  override fun changePin(currentPinHex: String, newPinHex: String, promise: Promise) =
    executeCommand(promise) {
      val current = hexToBytes(currentPinHex)
      val updated = hexToBytes(newPinHex)
      val payload = ByteArray(1 + current.size + 1 + updated.size)
      payload[0] = current.size.toByte()
      System.arraycopy(current, 0, payload, 1, current.size)
      payload[1 + current.size] = updated.size.toByte()
      System.arraycopy(updated, 0, payload, 2 + current.size, updated.size)

      val apdu = buildApdu(INS_CHANGE_PIN, 0x00, 0x00, payload, leIncluded = true)
      val (_, sw) = transceiveApdu(apdu)
      ensureSuccess(sw)
      promise.resolve(null)
    }

  override fun addListener(eventName: String) {
    // Required by RN's NativeEventEmitter contract; events are broadcast globally.
  }

  override fun removeListeners(count: Double) {
    // Required by RN's NativeEventEmitter contract; events are broadcast globally.
  }

  // MARK: - Command sequencing

  private fun doSelectApplication() {
    val apdu = buildApdu(INS_SELECT_APPLICATION, 0x04, 0x00, AID, leIncluded = true)
    val (_, sw) = transceiveApdu(apdu)
    ensureSuccess(sw)
  }

  private fun doGetKeyInfo(keyIndex: Int): WritableMap {
    val apdu = buildApdu(INS_GET_KEY_INFO, keyIndex, 0x00, null, leIncluded = true)
    val (data, sw) = transceiveApdu(apdu)
    ensureSuccess(sw)
    val map = Arguments.createMap()
    map.putString("publicKeyHex", bytesToHex(sliceOrEmpty(data, 8, 65)))
    map.putDouble("globalSigCounter", bytesToUnsignedLong(sliceOrEmpty(data, 0, 4)).toDouble())
    map.putDouble("sigCounter", bytesToUnsignedLong(sliceOrEmpty(data, 4, 4)).toDouble())
    return map
  }

  private fun doGenerateKeyPair(curveIndex: Int): Int {
    val apdu = buildApdu(INS_GENERATE_KEYPAIR, curveIndex, 0x00, null, leIncluded = true)
    val (data, sw) = transceiveApdu(apdu)
    ensureSuccess(sw)
    if (data.size != 1) {
      throw ApduException(CODE_INVALID_RESPONSE, "GENERATE_KEY returned an unexpected response")
    }
    return data[0].toInt() and 0xFF
  }

  private fun doGetOrCreateKey(keyIndex: Int, curveIndex: Int): WritableMap {
    while (true) {
      try {
        return doGetKeyInfo(keyIndex)
      } catch (e: ApduException) {
        if (e.code != swErrorCode(SW_KEY_WITH_IDX_NOT_AVAILABLE)) {
          throw e
        }
        doGenerateKeyPair(curveIndex)
      }
    }
  }

  // MARK: - Transceive plumbing

  private fun transceiveApdu(command: ByteArray): Pair<ByteArray, Int> {
    val isoDep = currentIsoDep
      ?: throw ApduException(CODE_NO_ACTIVE_SESSION, "No card connected. Call startSession() first.")
    val response = try {
      isoDep.transceive(command)
    } catch (e: IOException) {
      throw ApduException(CODE_IO_ERROR, e.message ?: "NFC I/O error")
    }
    if (response.size < 2) {
      throw ApduException(CODE_INVALID_RESPONSE, "Response APDU shorter than 2 bytes")
    }
    val data = if (response.size > 2) response.copyOfRange(0, response.size - 2) else ByteArray(0)
    val sw1 = response[response.size - 2].toInt() and 0xFF
    val sw2 = response[response.size - 1].toInt() and 0xFF
    return Pair(data, (sw1 shl 8) or sw2)
  }

  private fun closeCurrentTag() {
    try {
      currentIsoDep?.close()
    } catch (_: IOException) {
      // ignore, tag is being discarded anyway
    }
    currentIsoDep = null
  }

  private fun executeCommand(promise: Promise, action: () -> Unit) {
    try {
      action()
    } catch (e: ApduException) {
      promise.reject(e.code, e.message, e)
    } catch (e: IllegalArgumentException) {
      promise.reject(CODE_INVALID_ARGUMENT, e.message, e)
    } catch (e: Exception) {
      promise.reject(CODE_UNEXPECTED_ERROR, e.message, e)
    }
  }

  private fun emitEvent(payload: WritableMap) {
    try {
      reactContext.getJSModule(RCTDeviceEventEmitter::class.java).emit(EVENT_NAME, payload)
    } catch (_: Exception) {
      // JS context not ready yet; drop the event.
    }
  }

  private fun eventPayload(type: String, message: String?): WritableMap {
    val map = Arguments.createMap()
    map.putString("type", type)
    if (message != null) {
      map.putString("message", message)
    }
    return map
  }

  private class ApduException(val code: String, message: String) : Exception(message)

  companion object {
    const val NAME = NativeBlockchainSecurity2goSpec.NAME

    private const val EVENT_NAME = "BlockchainSecurity2goEvent"
    private const val TRANSCEIVE_TIMEOUT_MS = 5000

    // ISO7816 status words
    private const val SW_SUCCESS = 0x9000
    private const val SW_SUCCESS_WITH_RESPONSE_PREFIX = 0x61
    private const val SW_KEY_WITH_IDX_NOT_AVAILABLE = 0x6A88

    // Instruction bytes, as defined by the Blockchain Security2Go applet
    private const val INS_SELECT_APPLICATION = 0xA4
    private const val INS_GENERATE_KEYPAIR = 0x02
    private const val INS_GET_KEY_INFO = 0x16
    private const val INS_GENERATE_SIGNATURE = 0x18
    private const val INS_GENERATE_KEY_FROM_SEED = 0x20
    private const val INS_SET_PIN = 0x40
    private const val INS_CHANGE_PIN = 0x42
    private const val INS_VERIFY_PIN = 0x44
    private const val INS_UNLOCK_PIN = 0x46

    private const val CODE_NO_ACTIVITY = "NO_ACTIVITY"
    private const val CODE_NFC_NOT_SUPPORTED = "NFC_NOT_SUPPORTED"
    private const val CODE_NO_ACTIVE_SESSION = "NO_ACTIVE_SESSION"
    private const val CODE_UNSUPPORTED_TAG = "UNSUPPORTED_TAG"
    private const val CODE_IO_ERROR = "IO_ERROR"
    private const val CODE_INVALID_RESPONSE = "INVALID_RESPONSE"
    private const val CODE_INVALID_ARGUMENT = "INVALID_ARGUMENT"
    private const val CODE_UNEXPECTED_ERROR = "UNEXPECTED_ERROR"

    // AID of the Blockchain Security2Go applet
    private val AID = hexToBytes("D2760000041502000100000001")

    private fun swErrorCode(sw: Int): String = "SW_%04X".format(sw)

    private fun ensureSuccess(sw: Int) {
      val success = sw == SW_SUCCESS || (sw ushr 8) == SW_SUCCESS_WITH_RESPONSE_PREFIX
      if (!success) {
        throw ApduException(swErrorCode(sw), "Card returned status word %04X".format(sw))
      }
    }

    private fun buildApdu(ins: Int, p1: Int, p2: Int, data: ByteArray?, leIncluded: Boolean): ByteArray {
      val dataLength = data?.size ?: 0
      require(dataLength <= 0xFF) { "APDU data cannot be larger than 0xFF bytes" }

      var length = 4
      if (dataLength != 0) length += 1 + dataLength
      if (leIncluded) length += 1

      val apdu = ByteArray(length)
      var index = 0
      apdu[index++] = 0x00 // CLA
      apdu[index++] = ins.toByte()
      apdu[index++] = p1.toByte()
      apdu[index++] = p2.toByte()
      if (dataLength != 0) {
        apdu[index++] = dataLength.toByte()
        System.arraycopy(data!!, 0, apdu, index, dataLength)
        index += dataLength
      }
      if (leIncluded) {
        apdu[index] = 0x00
      }
      return apdu
    }

    private fun swBytes(sw: Int): ByteArray =
      byteArrayOf(((sw ushr 8) and 0xFF).toByte(), (sw and 0xFF).toByte())

    private fun sliceOrEmpty(data: ByteArray, offset: Int, length: Int): ByteArray {
      if (offset >= data.size) return ByteArray(0)
      val end = minOf(offset + length, data.size)
      return data.copyOfRange(offset, end)
    }

    private fun bytesToUnsignedLong(bytes: ByteArray): Long {
      var value = 0L
      for (b in bytes) {
        value = (value shl 8) or (b.toLong() and 0xFF)
      }
      return value
    }

    private fun hexToBytes(hex: String): ByteArray {
      val clean = hex.trim()
      require(clean.length % 2 == 0) { "Hex string must have an even length" }
      val result = ByteArray(clean.length / 2)
      for (i in result.indices) {
        val hi = Character.digit(clean[i * 2], 16)
        val lo = Character.digit(clean[i * 2 + 1], 16)
        require(hi >= 0 && lo >= 0) { "Invalid hex string" }
        result[i] = ((hi shl 4) + lo).toByte()
      }
      return result
    }

    private fun bytesToHex(bytes: ByteArray): String {
      val sb = StringBuilder(bytes.size * 2)
      for (b in bytes) sb.append("%02X".format(b))
      return sb.toString()
    }
  }
}
