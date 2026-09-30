#import <Foundation/Foundation.h>

@interface PPAPIKey : NSObject

- (void)loading:(void (^)(void))execute;
- (void)setPackageToken:(NSString *)token;
- (void)setOKText:(NSString *)newSubmitText;
- (void)setContactText:(NSString *)newContactText;
- (void)setAppVersion:(NSString *)newAppVersion;
- (void)setENLanguage:(BOOL)value;
- (void)exitKey;
- (void)copyKey;
- (void)showCSAL:(NSString *)title message:(NSString *)message apiKeyLabel:(NSString *)apiKeyLabel doneTime:(NSInteger)doneTime;

- (NSString *)getKey;
- (NSString *)getKeyExpire;
- (NSString *)getKeyAmount;
- (NSString *)getUDID;
- (NSString *)getDeviceName;
- (NSString *)getiOSVersion;
- (NSString *)getAppVersion;
- (NSString *)getAppName;
- (NSString *)getAppBundle;
- (NSString *)getJailbreakStatus;

@end