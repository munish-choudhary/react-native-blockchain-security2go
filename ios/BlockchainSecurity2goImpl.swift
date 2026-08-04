import CoreNFC
import Foundation

/// Wraps the ISO7816 APDU protocol used by the Infineon Blockchain
/// Security2Go secure element, ported from the reference Android/iOS sample
/// apps: SELECT_APPLICATION -> GET_KEY_INFO / GENERATE_KEY /
/// GENERATE_SIGNATURE / SET_PIN / VERIFY_PIN / UNLOCK_PIN / CHANGE_PIN.
///
/// Kept independent of React Native types: the ObjC++ bridge
/// (BlockchainSecurity2go.mm) adapts these plain closures to
/// RCTPromiseResolveBlock/RCTPromiseRejectBlock.
@objc(BlockchainSecurity2goImpl)
public class BlockchainSecurity2goImpl: NSObject, NFCTagReaderSessionDelegate {

  /// Forwards NFC lifecycle events (type, optional message) to JS.
  @objc public var onSessionEvent: ((String, String?) -> Void)?

  private var readerSession: NFCTagReaderSession?
  private var connectedTag: NFCISO7816Tag?
  private var startResolve: (() -> Void)?
  private var startReject: ((String, String) -> Void)?

  private struct CommandError: Error {
    let code: String
    let message: String
  }

  private typealias RawResult = Result<(data: Data, sw: Int), CommandError>

  // MARK: - Public (bridged) API

  @objc(isNfcSupported)
  public func isNfcSupported() -> Bool {
    return NFCTagReaderSession.readingAvailable
  }

  @objc(startSessionWithAlertMessage:resolve:reject:)
  public func startSession(
    alertMessage: String,
    resolve: @escaping () -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    guard NFCTagReaderSession.readingAvailable else {
      reject("NFC_NOT_SUPPORTED", "This device does not support NFC")
      return
    }
    connectedTag = nil
    startResolve = resolve
    startReject = reject

    let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
    session?.alertMessage = alertMessage
    readerSession = session
    session?.begin()
  }

  @objc(stopSessionWithResolve:reject:)
  public func stopSession(resolve: @escaping () -> Void, reject: @escaping (String, String) -> Void) {
    readerSession?.invalidate()
    readerSession = nil
    connectedTag = nil
    startResolve = nil
    startReject = nil
    onSessionEvent?("sessionInvalidated", nil)
    resolve()
  }

  @objc(transceiveWithApduHex:resolve:reject:)
  public func transceive(
    apduHex: String,
    resolve: @escaping (String) -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    guard let command = Self.hexToData(apduHex) else {
      reject("INVALID_ARGUMENT", "Invalid hex string")
      return
    }
    sendRaw(command) { (result: RawResult) in
      switch result {
      case .success(let response):
        resolve(Self.dataToHex(response.data) + String(format: "%04X", response.sw))
      case .failure(let error):
        reject(error.code, error.message)
      }
    }
  }

  @objc(selectApplication:reject:)
  public func selectApplication(resolve: @escaping (Bool) -> Void, reject: @escaping (String, String) -> Void) {
    performSelectApplication { (result: Result<Void, CommandError>) in
      switch result {
      case .success:
        resolve(true)
      case .failure(let error):
        reject(error.code, error.message)
      }
    }
  }

  @objc(getKeyInfo:resolve:reject:)
  public func getKeyInfo(
    keyIndex: Int,
    resolve: @escaping ([String: Any]) -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    performGetKeyInfo(keyIndex: keyIndex) { (result: Result<[String: Any], CommandError>) in
      switch result {
      case .success(let map):
        resolve(map)
      case .failure(let error):
        reject(error.code, error.message)
      }
    }
  }

  @objc(generateKeyPair:resolve:reject:)
  public func generateKeyPair(
    curveIndex: Int,
    resolve: @escaping (Int) -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    performGenerateKeyPair(curveIndex: curveIndex) { (result: Result<Int, CommandError>) in
      switch result {
      case .success(let newIndex):
        resolve(newIndex)
      case .failure(let error):
        reject(error.code, error.message)
      }
    }
  }

  @objc(generateKeyFromSeed:resolve:reject:)
  public func generateKeyFromSeed(
    seedHex: String,
    resolve: @escaping () -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    guard let seed = Self.hexToData(seedHex) else {
      reject("INVALID_ARGUMENT", "Invalid hex string")
      return
    }
    let apdu = Self.buildApdu(ins: Self.INS_GENERATE_KEY_FROM_SEED, p1: 0x00, p2: 0x00, data: seed, leIncluded: false)
    sendRawResolvingVoid(apdu, resolve: resolve, reject: reject)
  }

  @objc(getOrCreateKey:curveIndex:resolve:reject:)
  public func getOrCreateKey(
    keyIndex: Int,
    curveIndex: Int,
    resolve: @escaping ([String: Any]) -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    performSelectApplication { [weak self] (result: Result<Void, CommandError>) in
      guard let self = self else { return }
      switch result {
      case .success:
        self.performGetOrCreateKey(keyIndex: keyIndex, curveIndex: curveIndex) { keyResult in
          switch keyResult {
          case .success(let map):
            resolve(map)
          case .failure(let error):
            reject(error.code, error.message)
          }
        }
      case .failure(let error):
        reject(error.code, error.message)
      }
    }
  }

  @objc(generateSignature:hashHex:resolve:reject:)
  public func generateSignature(
    keyIndex: Int,
    hashHex: String,
    resolve: @escaping ([String: Any]) -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    guard let hash = Self.hexToData(hashHex) else {
      reject("INVALID_ARGUMENT", "Invalid hex string")
      return
    }
    let apdu = Self.buildApdu(
      ins: Self.INS_GENERATE_SIGNATURE, p1: UInt8(truncatingIfNeeded: keyIndex), p2: 0x00, data: hash,
      leIncluded: true
    )
    sendRaw(apdu) { (result: RawResult) in
      switch result {
      case .success(let response):
        if let error = Self.checkSuccess(response.sw) {
          reject(error.code, error.message)
          return
        }
        guard response.data.count >= 8 else {
          reject("INVALID_RESPONSE", "GENERATE_SIGNATURE response too short")
          return
        }
        var map: [String: Any] = [:]
        map["signatureHex"] = Self.dataToHex(Self.slice(response.data, offset: 8, length: response.data.count - 8))
        map["globalSigCounter"] = Self.bytesToUnsignedInt(Self.slice(response.data, offset: 0, length: 4))
        map["sigCounter"] = Self.bytesToUnsignedInt(Self.slice(response.data, offset: 4, length: 4))
        resolve(map)
      case .failure(let error):
        reject(error.code, error.message)
      }
    }
  }

  @objc(setPin:resolve:reject:)
  public func setPin(pinHex: String, resolve: @escaping () -> Void, reject: @escaping (String, String) -> Void) {
    guard let pin = Self.hexToData(pinHex) else {
      reject("INVALID_ARGUMENT", "Invalid hex string")
      return
    }
    let apdu = Self.buildApdu(ins: Self.INS_SET_PIN, p1: 0x00, p2: 0x00, data: pin, leIncluded: true)
    sendRawResolvingVoid(apdu, resolve: resolve, reject: reject)
  }

  @objc(verifyPin:resolve:reject:)
  public func verifyPin(pinHex: String, resolve: @escaping () -> Void, reject: @escaping (String, String) -> Void) {
    guard let pin = Self.hexToData(pinHex) else {
      reject("INVALID_ARGUMENT", "Invalid hex string")
      return
    }
    let apdu = Self.buildApdu(ins: Self.INS_VERIFY_PIN, p1: 0x00, p2: 0x00, data: pin, leIncluded: false)
    sendRawResolvingVoid(apdu, resolve: resolve, reject: reject)
  }

  @objc(unlockPin:resolve:reject:)
  public func unlockPin(pukHex: String, resolve: @escaping () -> Void, reject: @escaping (String, String) -> Void) {
    guard let puk = Self.hexToData(pukHex) else {
      reject("INVALID_ARGUMENT", "Invalid hex string")
      return
    }
    let apdu = Self.buildApdu(ins: Self.INS_UNLOCK_PIN, p1: 0x00, p2: 0x00, data: puk, leIncluded: false)
    sendRawResolvingVoid(apdu, resolve: resolve, reject: reject)
  }

  @objc(changePin:newPinHex:resolve:reject:)
  public func changePin(
    currentPinHex: String,
    newPinHex: String,
    resolve: @escaping () -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    guard let current = Self.hexToData(currentPinHex), let updated = Self.hexToData(newPinHex) else {
      reject("INVALID_ARGUMENT", "Invalid hex string")
      return
    }
    var payload = Data()
    payload.append(UInt8(truncatingIfNeeded: current.count))
    payload.append(current)
    payload.append(UInt8(truncatingIfNeeded: updated.count))
    payload.append(updated)

    let apdu = Self.buildApdu(ins: Self.INS_CHANGE_PIN, p1: 0x00, p2: 0x00, data: payload, leIncluded: true)
    sendRawResolvingVoid(apdu, resolve: resolve, reject: reject)
  }

  // MARK: - NFCTagReaderSessionDelegate

  public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
    // No-op: nothing to do until a tag is detected.
  }

  public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
    connectedTag = nil
    if let reject = startReject {
      reject("IO_ERROR", error.localizedDescription)
      startResolve = nil
      startReject = nil
    }
    onSessionEvent?("sessionInvalidated", error.localizedDescription)
  }

  public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
    guard tags.count == 1, case let NFCTag.iso7816(tag) = tags[0] else {
      session.invalidate(errorMessage: "Multiple or unsupported tags detected")
      startReject?("UNSUPPORTED_TAG", "Multiple or unsupported tags detected")
      startResolve = nil
      startReject = nil
      return
    }

    session.connect(to: tags[0]) { [weak self] error in
      guard let self = self else { return }
      if let error = error {
        self.startReject?("IO_ERROR", error.localizedDescription)
        self.startResolve = nil
        self.startReject = nil
        return
      }
      self.connectedTag = tag
      self.onSessionEvent?("tagDetected", nil)
      self.startResolve?()
      self.startResolve = nil
      self.startReject = nil
    }
  }

  // MARK: - Command sequencing

  private func performSelectApplication(completion: @escaping (Result<Void, CommandError>) -> Void) {
    let apdu = Self.buildApdu(ins: Self.INS_SELECT_APPLICATION, p1: 0x04, p2: 0x00, data: Self.AID, leIncluded: true)
    sendRaw(apdu) { (result: RawResult) in
      switch result {
      case .success(let response):
        if let error = Self.checkSuccess(response.sw) {
          completion(.failure(error))
        } else {
          completion(.success(()))
        }
      case .failure(let error):
        completion(.failure(error))
      }
    }
  }

  private func performGetKeyInfo(
    keyIndex: Int,
    completion: @escaping (Result<[String: Any], CommandError>) -> Void
  ) {
    let apdu = Self.buildApdu(
      ins: Self.INS_GET_KEY_INFO, p1: UInt8(truncatingIfNeeded: keyIndex), p2: 0x00, data: nil, leIncluded: true
    )
    sendRaw(apdu) { (result: RawResult) in
      switch result {
      case .success(let response):
        if let error = Self.checkSuccess(response.sw) {
          completion(.failure(error))
          return
        }
        var map: [String: Any] = [:]
        map["publicKeyHex"] = Self.dataToHex(Self.slice(response.data, offset: 8, length: 65))
        map["globalSigCounter"] = Self.bytesToUnsignedInt(Self.slice(response.data, offset: 0, length: 4))
        map["sigCounter"] = Self.bytesToUnsignedInt(Self.slice(response.data, offset: 4, length: 4))
        completion(.success(map))
      case .failure(let error):
        completion(.failure(error))
      }
    }
  }

  private func performGenerateKeyPair(
    curveIndex: Int,
    completion: @escaping (Result<Int, CommandError>) -> Void
  ) {
    let apdu = Self.buildApdu(
      ins: Self.INS_GENERATE_KEYPAIR, p1: UInt8(truncatingIfNeeded: curveIndex), p2: 0x00, data: nil,
      leIncluded: true
    )
    sendRaw(apdu) { (result: RawResult) in
      switch result {
      case .success(let response):
        if let error = Self.checkSuccess(response.sw) {
          completion(.failure(error))
          return
        }
        guard response.data.count == 1 else {
          completion(.failure(CommandError(code: "INVALID_RESPONSE", message: "GENERATE_KEY returned an unexpected response")))
          return
        }
        completion(.success(Int(response.data[response.data.startIndex])))
      case .failure(let error):
        completion(.failure(error))
      }
    }
  }

  private func performGetOrCreateKey(
    keyIndex: Int,
    curveIndex: Int,
    completion: @escaping (Result<[String: Any], CommandError>) -> Void
  ) {
    performGetKeyInfo(keyIndex: keyIndex) { [weak self] (result: Result<[String: Any], CommandError>) in
      guard let self = self else { return }
      switch result {
      case .success(let map):
        completion(.success(map))
      case .failure(let error):
        guard error.code == Self.swErrorCode(Self.SW_KEY_WITH_IDX_NOT_AVAILABLE) else {
          completion(.failure(error))
          return
        }
        self.performGenerateKeyPair(curveIndex: curveIndex) { genResult in
          switch genResult {
          case .success:
            self.performGetOrCreateKey(keyIndex: keyIndex, curveIndex: curveIndex, completion: completion)
          case .failure(let genError):
            completion(.failure(genError))
          }
        }
      }
    }
  }

  // MARK: - Transceive plumbing

  private func sendRaw(_ command: Data, completion: @escaping (RawResult) -> Void) {
    guard let tag = connectedTag else {
      completion(.failure(CommandError(code: "NO_ACTIVE_SESSION", message: "No card connected. Call startSession() first.")))
      return
    }
    guard let apdu = NFCISO7816APDU(data: command) else {
      completion(.failure(CommandError(code: "INVALID_ARGUMENT", message: "Malformed APDU bytes")))
      return
    }
    tag.sendCommand(apdu: apdu) { (responseData: Data, sw1: UInt8, sw2: UInt8, error: Error?) in
      if let error = error {
        completion(.failure(CommandError(code: "IO_ERROR", message: error.localizedDescription)))
        return
      }
      let sw = (Int(sw1) << 8) | Int(sw2)
      completion(.success((data: responseData, sw: sw)))
    }
  }

  private func sendRawResolvingVoid(
    _ command: Data,
    resolve: @escaping () -> Void,
    reject: @escaping (String, String) -> Void
  ) {
    sendRaw(command) { (result: RawResult) in
      switch result {
      case .success(let response):
        if let error = Self.checkSuccess(response.sw) {
          reject(error.code, error.message)
        } else {
          resolve()
        }
      case .failure(let error):
        reject(error.code, error.message)
      }
    }
  }

  // MARK: - APDU protocol constants & helpers

  // ISO7816 status words
  private static let SW_SUCCESS = 0x9000
  private static let SW_SUCCESS_WITH_RESPONSE_PREFIX = 0x61
  private static let SW_KEY_WITH_IDX_NOT_AVAILABLE = 0x6A88

  // Instruction bytes, as defined by the Blockchain Security2Go applet
  private static let INS_SELECT_APPLICATION: UInt8 = 0xA4
  private static let INS_GENERATE_KEYPAIR: UInt8 = 0x02
  private static let INS_GET_KEY_INFO: UInt8 = 0x16
  private static let INS_GENERATE_SIGNATURE: UInt8 = 0x18
  private static let INS_GENERATE_KEY_FROM_SEED: UInt8 = 0x20
  private static let INS_SET_PIN: UInt8 = 0x40
  private static let INS_CHANGE_PIN: UInt8 = 0x42
  private static let INS_VERIFY_PIN: UInt8 = 0x44
  private static let INS_UNLOCK_PIN: UInt8 = 0x46

  // AID of the Blockchain Security2Go applet
  private static let AID = hexToData("D2760000041502000100000001")!

  private static func swErrorCode(_ sw: Int) -> String {
    return String(format: "SW_%04X", sw)
  }

  private static func checkSuccess(_ sw: Int) -> CommandError? {
    let success = sw == SW_SUCCESS || (sw >> 8) == SW_SUCCESS_WITH_RESPONSE_PREFIX
    if success { return nil }
    return CommandError(code: swErrorCode(sw), message: "Card returned status word \(String(format: "%04X", sw))")
  }

  private static func buildApdu(ins: UInt8, p1: UInt8, p2: UInt8, data: Data?, leIncluded: Bool) -> Data {
    var apdu = Data([0x00, ins, p1, p2])
    if let data = data, !data.isEmpty {
      apdu.append(UInt8(truncatingIfNeeded: data.count))
      apdu.append(data)
    }
    if leIncluded {
      apdu.append(0x00)
    }
    return apdu
  }

  private static func slice(_ data: Data, offset: Int, length: Int) -> Data {
    let bytes = [UInt8](data)
    guard offset < bytes.count else { return Data() }
    let end = min(offset + length, bytes.count)
    return Data(bytes[offset..<end])
  }

  private static func bytesToUnsignedInt(_ data: Data) -> Int {
    var value = 0
    for byte in data {
      value = (value << 8) | Int(byte)
    }
    return value
  }

  private static func hexToData(_ hex: String) -> Data? {
    let clean = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard clean.count % 2 == 0 else { return nil }
    var data = Data(capacity: clean.count / 2)
    var index = clean.startIndex
    while index < clean.endIndex {
      let nextIndex = clean.index(index, offsetBy: 2)
      guard let byte = UInt8(clean[index..<nextIndex], radix: 16) else { return nil }
      data.append(byte)
      index = nextIndex
    }
    return data
  }

  private static func dataToHex(_ data: Data) -> String {
    return data.map { String(format: "%02X", $0) }.joined()
  }
}
