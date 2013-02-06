//
//  OcraTests.m
//  MobileAuth
//
//  Created by Ivo Jansch on 3/14/11.
//  Copyright 2011 Egeniq. All rights reserved.
//

#import "OcraTests.h"

#import "OCRA.h"

#define KEY_20 @"3132333435363738393031323334353637383930"
#define KEY_32 @"3132333435363738393031323334353637383930313233343536373839303132"
#define KEY_64 @"31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"

#define PIN_1234_HASH @"7110eda4d09e062aa5e4a390b0a572ac0d2c0220"

@implementation OcraTests

- (NSString*) qHex: (NSString *)str {
    
    NSDecimalNumber *bigNumberValue = [NSDecimalNumber decimalNumberWithString:str];
    return [NSString stringWithFormat:@"%X", [bigNumberValue intValue]];
}

- (void)testC1PlainChallengeResponse {
    
    NSError *error;
    NSString *suite = @"OCRA-1:HOTP-SHA1-6:QN08";
        
    STAssertEqualObjects(@"237653", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"00000000"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"243178", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"11111111"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"653583", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"22222222"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"740991", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"33333333"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"608993", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"44444444"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"388898", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"55555555"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"816933", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"66666666"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"224598", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"77777777"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"750600", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"88888888"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"294470", [OCRA generateOCRAForSuite:suite key:KEY_20 counter:nil question:[self qHex:@"99999999"] password:nil sessionInformation:nil timestamp:nil error:&error], @"Test");
    
    suite = @"OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
    
    STAssertEqualObjects(@"65347737", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"0" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"86775851", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"1" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"78192410", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"2" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"71565254", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"3" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"10104329", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"4" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"65983500", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"5" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"70069104", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"6" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"91771096", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"7" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"75011558", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"8" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"08522129", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:@"9" question:[self qHex:@"12345678"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    
    suite = @"OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
    
    STAssertEqualObjects(@"83238735", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:nil question:[self qHex:@"00000000"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"01501458", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:nil question:[self qHex:@"11111111"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"17957585", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:nil question:[self qHex:@"22222222"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"86776967", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:nil question:[self qHex:@"33333333"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"86807031", [OCRA generateOCRAForSuite:suite key:KEY_32 counter:nil question:[self qHex:@"44444444"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    
    suite = @"OCRA-1:HOTP-SHA512-8:C-QN08";
    
    STAssertEqualObjects(@"07016083", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00000" question:[self qHex:@"00000000"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"63947962", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00001" question:[self qHex:@"11111111"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"70123924", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00002" question:[self qHex:@"22222222"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"25341727", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00003" question:[self qHex:@"33333333"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"33203315", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00004" question:[self qHex:@"44444444"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"34205738", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00005" question:[self qHex:@"55555555"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"44343969", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00006" question:[self qHex:@"66666666"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"51946085", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00007" question:[self qHex:@"77777777"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"20403879", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00008" question:[self qHex:@"88888888"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");
    STAssertEqualObjects(@"31409299", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:@"00009" question:[self qHex:@"99999999"] password:PIN_1234_HASH sessionInformation:nil timestamp:nil error:&error], @"Test");

    suite = @"OCRA-1:HOTP-SHA512-8:QN08-T1M";

    STAssertEqualObjects(@"95209754", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:nil question:[self qHex:@"00000000"] password:nil sessionInformation:nil timestamp:@"132d0b6" error:&error], @"Test");
    STAssertEqualObjects(@"55907591", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:nil question:[self qHex:@"11111111"] password:nil sessionInformation:nil timestamp:@"132d0b6" error:&error], @"Test");
    STAssertEqualObjects(@"22048402", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:nil question:[self qHex:@"22222222"] password:nil sessionInformation:nil timestamp:@"132d0b6" error:&error], @"Test");
    STAssertEqualObjects(@"24218844", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:nil question:[self qHex:@"33333333"] password:nil sessionInformation:nil timestamp:@"132d0b6" error:&error], @"Test");
    STAssertEqualObjects(@"36209546", [OCRA generateOCRAForSuite:suite key:KEY_64 counter:nil question:[self qHex:@"44444444"] password:nil sessionInformation:nil timestamp:@"132d0b6" error:&error], @"Test");

}



@end
