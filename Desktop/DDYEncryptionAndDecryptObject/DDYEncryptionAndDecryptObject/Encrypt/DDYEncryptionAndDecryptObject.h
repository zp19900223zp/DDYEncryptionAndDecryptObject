//
//  DDYEncryptionAndDecryptObject.h
//  AH_Enterprise
//
//  Created by AOHY on 2018/3/1.
//  Copyright © 2018年 Mr.Yang. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface DDYEncryptionAndDecryptObject : NSObject


/**
 加密
 return string
 */
+ (NSString *)encryptKey;
+ (NSString *)encryptString:(NSString *)string;

/**
 获取验签
 */
+ (NSString *)singObtainAttestation:(NSString *)string;

/**
 加密数据
 */
+ (NSString *)encryptAESData:(NSString *)string;

/**
 解密RSA对16为随机数字或字母
 */
+ (NSString *)decryptString:(NSString *)string;

/**
 AES 解密 后台传过来的数据
 */
+ (NSData *)decryptAESData:(NSString *)data key:(NSString *)key;

/**
 客户端公钥
 */
+ (NSString *)ClientPublicKey;

/**
 获取随机的key值
 */
+(void)obtainRandomKey;

/**
 验证签名
 */
+(BOOL)verifyString:(NSString *)string withSign:(NSString *)signString;

@end
