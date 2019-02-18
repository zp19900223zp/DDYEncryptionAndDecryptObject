//
//  ViewController.m
//  DDYEncryptionAndDecryptObject
//
//  Created by AOHY on 2019/2/18.
//  Copyright © 2019年 Config. All rights reserved.
//

#import "ViewController.h"
#import "DDYEncryptionAndDecryptObject.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *textFields;
@property (weak, nonatomic) IBOutlet UILabel *textLabel;
@property (weak, nonatomic) IBOutlet UILabel *jiemiLabel;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}
- (IBAction)jiami:(id)sender {
    [self.textFields resignFirstResponder];
    // 对传参数加密
    NSString *rsaParams = [DDYEncryptionAndDecryptObject encryptString:self.textFields.text];
    self.textLabel.text = rsaParams;
}


- (IBAction)jiemi:(id)sender {
    NSString *jiemi = [DDYEncryptionAndDecryptObject decryptString:self.textLabel.text];
    self.jiemiLabel.text = jiemi;
    NSLog(@"123");
}



@end
