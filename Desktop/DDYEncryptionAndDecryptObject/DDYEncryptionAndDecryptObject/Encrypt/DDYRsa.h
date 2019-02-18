//
//  DDYRsa.h
//  AH_Enterprise
//
//  Created by AOHY on 2018/2/28.
//  Copyright © 2018年 Mr.Yang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DDYRsa : NSObject

/**
 生成RSA密钥对
 */
+ (NSDictionary *)generateKeyPair;

/**
 RSA加密
 str : 加密的数据
 pubKey : 加密的公钥
 return base64 encoded string
 */
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 RSA加密
 data : 加密的数据
 pubKey : 加密的公钥
 return raw data
 */
+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey;

/**
 RSA加密
 str : 加密的数据
 pubKey : 加密的私钥
 return base64 encoded string
 */
+ (NSString *)encryptString:(NSString *)str privateKey:(NSString *)privKey;

/**
 RSA加密
 data : 加密的数据
 pubKey : 加密的私钥
 return raw data
 */
+ (NSData *)encryptData:(NSData *)data privateKey:(NSString *)privKey;

/**
 RSA解密
 str : 解密的数据
 pubKey : 解密的公钥
 return  string
 */
+ (NSString *)decryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 RSA解密
 str : 解密的数据
 pubKey : 解密的公钥
 return  data
 */
+ (NSData *)decryptData:(NSData *)data publicKey:(NSString *)pubKey;

/**
 RSA解密
 str : 解密的数据
 pubKey : 解密的私钥
 return  string
 */
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey;

/**
 RSA解密
 str : 解密的数据
 pubKey : 解密的私钥
 return  data
 */
+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey;

/**
 RSA获取签名
 */
+ (NSString *)signString:(NSString *)string withPrivatekey:(NSString *)privKey;

/**
 RSA验证签名
 */
+ (BOOL)verifyString:(NSString *)string withSign:(NSString *)signString pulicKey:(NSString *)pulicKey;

@end
