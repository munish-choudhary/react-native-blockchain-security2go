#import "BlockchainSecurity2go.h"
#import "BlockchainSecurity2go-Swift.h"

static NSString *const kEventName = @"BlockchainSecurity2goEvent";

@interface BlockchainSecurity2go ()
@property(nonatomic, strong) BlockchainSecurity2goImpl *impl;
@property(nonatomic, assign) BOOL hasListeners;
@end

@implementation BlockchainSecurity2go

- (instancetype)init
{
  self = [super init];
  if (self) {
    _impl = [BlockchainSecurity2goImpl new];

    __weak __typeof(self) weakSelf = self;
    _impl.onSessionEvent = ^(NSString *type, NSString *_Nullable message) {
      __typeof(self) strongSelf = weakSelf;
      if (strongSelf == nil || !strongSelf.hasListeners) {
        return;
      }
      NSMutableDictionary *body = [NSMutableDictionary dictionaryWithObject:type forKey:@"type"];
      if (message != nil) {
        body[@"message"] = message;
      }
      [strongSelf sendEventWithName:kEventName body:body];
    };
  }
  return self;
}

+ (NSString *)moduleName
{
  return @"BlockchainSecurity2go";
}

- (NSArray<NSString *> *)supportedEvents
{
  return @[ kEventName ];
}

- (void)startObserving
{
  self.hasListeners = YES;
}

- (void)stopObserving
{
  self.hasListeners = NO;
}

- (void)isNfcSupported:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  resolve(@([self.impl isNfcSupported]));
}

- (void)startSession:(NSString *)alertMessage
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject
{
  [self.impl startSessionWithAlertMessage:alertMessage
      resolve:^{
        resolve(nil);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)stopSession:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [self.impl stopSessionWithResolve:^{
    resolve(nil);
  }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)transceive:(NSString *)apduHex resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [self.impl transceiveWithApduHex:apduHex
      resolve:^(NSString *response) {
        resolve(response);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)selectApplication:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [self.impl selectApplication:^(BOOL success) {
    resolve(@(success));
  }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)getKeyInfo:(double)keyIndex resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [self.impl getKeyInfo:(NSInteger)keyIndex
      resolve:^(NSDictionary<NSString *, id> *result) {
        resolve(result);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)generateKeyPair:(double)curveIndex
                 resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject
{
  [self.impl generateKeyPair:(NSInteger)curveIndex
      resolve:^(NSInteger newIndex) {
        resolve(@(newIndex));
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)generateKeyFromSeed:(NSString *)seedHex
                     resolve:(RCTPromiseResolveBlock)resolve
                      reject:(RCTPromiseRejectBlock)reject
{
  [self.impl generateKeyFromSeed:seedHex
      resolve:^{
        resolve(nil);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)getOrCreateKey:(double)keyIndex
             curveIndex:(double)curveIndex
                resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject
{
  [self.impl getOrCreateKey:(NSInteger)keyIndex
      curveIndex:(NSInteger)curveIndex
      resolve:^(NSDictionary<NSString *, id> *result) {
        resolve(result);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)generateSignature:(double)keyIndex
                  hashHex:(NSString *)hashHex
                  resolve:(RCTPromiseResolveBlock)resolve
                   reject:(RCTPromiseRejectBlock)reject
{
  [self.impl generateSignature:(NSInteger)keyIndex
      hashHex:hashHex
      resolve:^(NSDictionary<NSString *, id> *result) {
        resolve(result);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)setPin:(NSString *)pinHex resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [self.impl setPin:pinHex
      resolve:^{
        resolve(nil);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)verifyPin:(NSString *)pinHex resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [self.impl verifyPin:pinHex
      resolve:^{
        resolve(nil);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)unlockPin:(NSString *)pukHex resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject
{
  [self.impl unlockPin:pukHex
      resolve:^{
        resolve(nil);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (void)changePin:(NSString *)currentPinHex
        newPinHex:(NSString *)newPinHex
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
  [self.impl changePin:currentPinHex
      newPinHex:newPinHex
      resolve:^{
        resolve(nil);
      }
      reject:^(NSString *code, NSString *message) {
        reject(code, message, nil);
      }];
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeBlockchainSecurity2goSpecJSI>(params);
}

@end
