<?php
/**
 * This file is part of the ocra-implementations package.
 *
 * More information: https://github.com/SURFnet/ocra-implementations/
 *
 * @author Ivo Jansch <ivo@egeniq.com>
 * 
 * @license See the LICENSE file in the source distribution
 */
 
require_once '../OCRA.php';

class ArrayTest extends PHPUnit_Framework_TestCase
{
    const KEY_20 = "3132333435363738393031323334353637383930";
    const KEY_32 = "3132333435363738393031323334353637383930313233343536373839303132";
    const KEY_64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";
    const PIN_1234_HASH = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";
    
    public function qHex($decimalChallenge)
    {
        return dechex($decimalChallenge);
    }    

    public function testC1OneWayChallengeResponse()
    {
        $suite = "OCRA-1:HOTP-SHA1-6:QN08";
        
        $this->assertEquals("237653", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("00000000"), null, null, null)); 
        $this->assertEquals("243178", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("11111111"), null, null, null));
        $this->assertEquals("653583", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("22222222"), null, null, null));
        $this->assertEquals("740991", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("33333333"), null, null, null));
        $this->assertEquals("608993", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("44444444"), null, null, null));
        $this->assertEquals("388898", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("55555555"), null, null, null));
        $this->assertEquals("816933", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("66666666"), null, null, null));
        $this->assertEquals("224598", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("77777777"), null, null, null));
        $this->assertEquals("750600", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("88888888"), null, null, null));
        $this->assertEquals("294470", OCRA::generateOCRA($suite, self::KEY_20, null, $this->qHex("99999999"), null, null, null));
        
        $suite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";

        $this->assertEquals("65347737", OCRA::generateOCRA($suite, self::KEY_32, "0", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("86775851", OCRA::generateOCRA($suite, self::KEY_32, "1", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("78192410", OCRA::generateOCRA($suite, self::KEY_32, "2", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("71565254", OCRA::generateOCRA($suite, self::KEY_32, "3", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("10104329", OCRA::generateOCRA($suite, self::KEY_32, "4", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("65983500", OCRA::generateOCRA($suite, self::KEY_32, "5", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("70069104", OCRA::generateOCRA($suite, self::KEY_32, "6", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("91771096", OCRA::generateOCRA($suite, self::KEY_32, "7", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("75011558", OCRA::generateOCRA($suite, self::KEY_32, "8", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("08522129", OCRA::generateOCRA($suite, self::KEY_32, "9", $this->qHex("12345678"), self::PIN_1234_HASH, null, null));

        $suite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
        
        $this->assertEquals("83238735", OCRA::generateOCRA($suite, self::KEY_32, null, $this->qHex("00000000"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("01501458", OCRA::generateOCRA($suite, self::KEY_32, null, $this->qHex("11111111"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("17957585", OCRA::generateOCRA($suite, self::KEY_32, null, $this->qHex("22222222"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("86776967", OCRA::generateOCRA($suite, self::KEY_32, null, $this->qHex("33333333"), self::PIN_1234_HASH, null, null));
        $this->assertEquals("86807031", OCRA::generateOCRA($suite, self::KEY_32, null, $this->qHex("44444444"), self::PIN_1234_HASH, null, null));
        
        $suite = "OCRA-1:HOTP-SHA512-8:C-QN08";
        
        $this->assertEquals("07016083", OCRA::generateOCRA($suite, self::KEY_64, "00000", $this->qHex("00000000"), null, null, null));
        $this->assertEquals("63947962", OCRA::generateOCRA($suite, self::KEY_64, "00001", $this->qHex("11111111"), null, null, null));
        $this->assertEquals("70123924", OCRA::generateOCRA($suite, self::KEY_64, "00002", $this->qHex("22222222"), null, null, null));
        $this->assertEquals("25341727", OCRA::generateOCRA($suite, self::KEY_64, "00003", $this->qHex("33333333"), null, null, null));
        $this->assertEquals("33203315", OCRA::generateOCRA($suite, self::KEY_64, "00004", $this->qHex("44444444"), null, null, null));
        $this->assertEquals("34205738", OCRA::generateOCRA($suite, self::KEY_64, "00005", $this->qHex("55555555"), null, null, null));
        $this->assertEquals("44343969", OCRA::generateOCRA($suite, self::KEY_64, "00006", $this->qHex("66666666"), null, null, null));
        $this->assertEquals("51946085", OCRA::generateOCRA($suite, self::KEY_64, "00007", $this->qHex("77777777"), null, null, null));
        $this->assertEquals("20403879", OCRA::generateOCRA($suite, self::KEY_64, "00008", $this->qHex("88888888"), null, null, null));
        $this->assertEquals("31409299", OCRA::generateOCRA($suite, self::KEY_64, "00009", $this->qHex("99999999"), null, null, null));
        
        $suite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
        
        $this->assertEquals("95209754", OCRA::generateOCRA($suite, self::KEY_64, null, $this->qHex("00000000"), null, null, "132d0b6"));
        $this->assertEquals("55907591", OCRA::generateOCRA($suite, self::KEY_64, null, $this->qHex("11111111"), null, null, "132d0b6"));
        $this->assertEquals("22048402", OCRA::generateOCRA($suite, self::KEY_64, null, $this->qHex("22222222"), null, null, "132d0b6"));
        $this->assertEquals("24218844", OCRA::generateOCRA($suite, self::KEY_64, null, $this->qHex("33333333"), null, null, "132d0b6"));
        $this->assertEquals("36209546", OCRA::generateOCRA($suite, self::KEY_64, null, $this->qHex("44444444"), null, null, "132d0b6"));
        
    }

}
