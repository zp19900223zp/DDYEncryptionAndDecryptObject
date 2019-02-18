//
//  DDYAes.h
//  AH_Enterprise
//
//  Created by AOHY on 2018/2/28.
//  Copyright © 2018年 Mr.Yang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DDYAes : NSObject

/**
 AES 加密
 */
+ (NSString *)encryptAES:(NSString *)content key:(NSString *)key;

/**
 AES 解密
 */
+ (NSData *)decryptAES:(NSString *)content key:(NSString *)key;

/**
 获取16为数字或者字母
 */
+ (NSString *)getRandom:(NSInteger)index;
@end
