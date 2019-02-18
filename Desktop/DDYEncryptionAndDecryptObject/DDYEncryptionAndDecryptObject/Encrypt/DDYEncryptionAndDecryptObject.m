//
//  DDYEncryptionAndDecryptObject.m
//  AH_Enterprise
//
//  Created by AOHY on 2018/3/1.
//  Copyright © 2018年 Mr.Yang. All rights reserved.
//

#import "DDYEncryptionAndDecryptObject.h"
#import "DDYRsa.h"
#import "DDYAes.h"

// 客户端私钥
#define clientPrivateKey @"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKbNojYr8KlqKD/yCOd7QXu3e4TsrHd4sz3XgDYWEZZgYqIjVDcpcnlztwomgjMj9xSxdpyCc85GOGa0lva1fNZpG6KXYS1xuFa9G7FRbaACoCL31TRv8t4TNkfQhQ7e2S7ZktqyUePWYLlzu8hx5jXdriErRIx1jWK1q1NeEd3NAgMBAAECgYAws7Ob+4JeBLfRy9pbs/ovpCf1bKEClQRIlyZBJHpoHKZPzt7k6D4bRfT4irvTMLoQmawXEGO9o3UOT8YQLHdRLitW1CYKLy8k8ycyNpB/1L2vP+kHDzmM6Pr0IvkFgnbIFQmXeS5NBV+xOdlAYzuPFkCyfUSOKdmt3F/Pbf9EhQJBANrF5Uaxmk7qGXfRV7tCT+f27eAWtYi2h/gJenLrmtkeHg7SkgDiYHErJDns85va4cnhaAzAI1eSIHVaXh3JGXcCQQDDL9ns78LNDr/QuHN9pmeDdlQfikeDKzW8dMcUIqGVX4WQJMptviZuf3cMvgm9+hDTVLvSePdTlA9YSCF4VNPbAkEAvbe54XlpCKBIX7iiLRkPdGiV1qu614j7FqUZlAkvKrPMeywuQygNXHZ+HuGWTIUfItQfSFdjDrEBBuPMFGZtdwJAV5N3xyyIjfMJM4AfKYhpN333HrOvhHX1xVnsHOew8lGKnvMy9Gx11+xPISN/QYMa24dQQo5OAm0TOXwbsF73MwJAHzqaKZPsEN08JunWDOKs3ZS+92maJIm1YGdYf5ipB8/Bm3wElnJsCiAeRqYKmPpAMlCZ5x+ZAsuC1sjcp2r7xw=="

// 客户端公钥
#define clientPublicKey @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmzaI2K/Cpaig/8gjne0F7t3uE7Kx3eLM914A2FhGWYGKiI1Q3KXJ5c7cKJoIzI/cUsXacgnPORjhmtJb2tXzWaRuil2EtcbhWvRuxUW2gAqAi99U0b/LeEzZH0IUO3tku2ZLaslHj1mC5c7vIceY13a4hK0SMdY1itatTXhHdzQIDAQAB"

// 服务端公钥
#define serverPublicKey @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyGffCqoC1vCDLeBvjfuHdw4johGvubOpQjEhhPzW1PbLSRKsNBLgj+eDGOiZE9BwmEwqy16sMOq0kMlhewTQlRrLJNlw3L0iogs9WTIGm3el1SuZLyMnMksnV0NCsuq538cPMNppZRwARb7NXmpmh0KM79fJ/1xqnpo1tgRcv4wIDAQAB"

@interface DDYEncryptionAndDecryptObject ()

//@property (nonatomic, copy) NSString *randomStr;

@end


@implementation DDYEncryptionAndDecryptObject

static NSString *randomStr;

/**
 加密16位随机数RSA
 return string
 */
+ (NSString *)encryptKey{
    NSString *encryptStr = @"";
    // 对16为随机数字或字母进行加密
    encryptStr = [DDYRsa encryptString:randomStr publicKey:serverPublicKey];
    return encryptStr;
}

+ (NSString *)encryptString:(NSString *)string{
   NSString *encryptStr = [DDYRsa encryptString:string publicKey:clientPublicKey];
    return encryptStr;
}

/**
 加密传参数据AES
 */
+ (NSString *)encryptAESData:(NSString *)string{
    return  [DDYAes encryptAES:string key:randomStr];
}

/**
 解密RSA对16为随机数字或字母
 */
+ (NSString *)decryptString:(NSString *)string{
   return  [DDYRsa decryptString:string privateKey:clientPrivateKey];
}

/**
 AES 解密 后台传过来的数据
 */
+ (NSData *)decryptAESData:(NSString *)data key:(NSString *)key{
    return  [DDYAes decryptAES:data key:key];
}

/**
 获取签名
 */
+ (NSString *)singObtainAttestation:(NSString *)string{
    return [DDYRsa signString:string withPrivatekey:clientPrivateKey];
}

/**
 验证签名
 */
+(BOOL)verifyString:(NSString *)string withSign:(NSString *)signString{
    return [DDYRsa verifyString:string withSign:signString pulicKey:serverPublicKey];
}

/**
 获取随机的key值
 */
+(void)obtainRandomKey{
    NSString *resStr = [DDYAes getRandom:16];
    randomStr = resStr;
}

/**
 客户端公钥
 */
+ (NSString *)ClientPublicKey{
    return clientPublicKey;
}


@end
