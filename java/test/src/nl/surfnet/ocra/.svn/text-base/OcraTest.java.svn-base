package nl.surfnet.ocra;

/**
 * The data used in this test case is taken from "Appendix C. Test Vectors" from the OCRA RFC at
 * http://tools.ietf.org/html/rfc6287 
 */

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Test;

public class OcraTest {

    private static final String KEY_20 = "3132333435363738393031323334353637383930";
    private static final String KEY_32 = "3132333435363738393031323334353637383930313233343536373839303132";
    private static final String KEY_64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";
    private static final String PIN_1234_HASH = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";
    
    // Note that challenge questions need to be passed in as hex!
    protected String qHex(String question) {
        return new String((new BigInteger(question, 10)).toString(16)).toUpperCase();
    }
    
    @Test
    public void test_C1_OneWayChallengeResponse() {
        
        String suite = "OCRA-1:HOTP-SHA1-6:QN08";
        
        assertEquals("237653", OCRA.generateOCRA(suite, KEY_20, null, qHex("00000000"), null, null, null));
        assertEquals("243178", OCRA.generateOCRA(suite, KEY_20, null, qHex("11111111"), null, null, null));
        assertEquals("653583", OCRA.generateOCRA(suite, KEY_20, null, qHex("22222222"), null, null, null));
        assertEquals("740991", OCRA.generateOCRA(suite, KEY_20, null, qHex("33333333"), null, null, null));
        assertEquals("608993", OCRA.generateOCRA(suite, KEY_20, null, qHex("44444444"), null, null, null));
        assertEquals("388898", OCRA.generateOCRA(suite, KEY_20, null, qHex("55555555"), null, null, null));
        assertEquals("816933", OCRA.generateOCRA(suite, KEY_20, null, qHex("66666666"), null, null, null));
        assertEquals("224598", OCRA.generateOCRA(suite, KEY_20, null, qHex("77777777"), null, null, null));
        assertEquals("750600", OCRA.generateOCRA(suite, KEY_20, null, qHex("88888888"), null, null, null));
        assertEquals("294470", OCRA.generateOCRA(suite, KEY_20, null, qHex("99999999"), null, null, null));
        
        suite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
        
        assertEquals("65347737", OCRA.generateOCRA(suite, KEY_32, "0", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("86775851", OCRA.generateOCRA(suite, KEY_32, "1", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("78192410", OCRA.generateOCRA(suite, KEY_32, "2", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("71565254", OCRA.generateOCRA(suite, KEY_32, "3", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("10104329", OCRA.generateOCRA(suite, KEY_32, "4", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("65983500", OCRA.generateOCRA(suite, KEY_32, "5", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("70069104", OCRA.generateOCRA(suite, KEY_32, "6", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("91771096", OCRA.generateOCRA(suite, KEY_32, "7", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("75011558", OCRA.generateOCRA(suite, KEY_32, "8", qHex("12345678"), PIN_1234_HASH, null, null));
        assertEquals("08522129", OCRA.generateOCRA(suite, KEY_32, "9", qHex("12345678"), PIN_1234_HASH, null, null));
        
        suite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
        
        assertEquals("83238735", OCRA.generateOCRA(suite, KEY_32, null, qHex("00000000"), PIN_1234_HASH, null, null));
        assertEquals("01501458", OCRA.generateOCRA(suite, KEY_32, null, qHex("11111111"), PIN_1234_HASH, null, null));
        assertEquals("17957585", OCRA.generateOCRA(suite, KEY_32, null, qHex("22222222"), PIN_1234_HASH, null, null));
        assertEquals("86776967", OCRA.generateOCRA(suite, KEY_32, null, qHex("33333333"), PIN_1234_HASH, null, null));
        assertEquals("86807031", OCRA.generateOCRA(suite, KEY_32, null, qHex("44444444"), PIN_1234_HASH, null, null));
        
        suite = "OCRA-1:HOTP-SHA512-8:C-QN08";
        
        assertEquals("07016083", OCRA.generateOCRA(suite, KEY_64, "00000", qHex("00000000"), null, null, null));
        assertEquals("63947962", OCRA.generateOCRA(suite, KEY_64, "00001", qHex("11111111"), null, null, null));
        assertEquals("70123924", OCRA.generateOCRA(suite, KEY_64, "00002", qHex("22222222"), null, null, null));
        assertEquals("25341727", OCRA.generateOCRA(suite, KEY_64, "00003", qHex("33333333"), null, null, null));
        assertEquals("33203315", OCRA.generateOCRA(suite, KEY_64, "00004", qHex("44444444"), null, null, null));
        assertEquals("34205738", OCRA.generateOCRA(suite, KEY_64, "00005", qHex("55555555"), null, null, null));
        assertEquals("44343969", OCRA.generateOCRA(suite, KEY_64, "00006", qHex("66666666"), null, null, null));
        assertEquals("51946085", OCRA.generateOCRA(suite, KEY_64, "00007", qHex("77777777"), null, null, null));
        assertEquals("20403879", OCRA.generateOCRA(suite, KEY_64, "00008", qHex("88888888"), null, null, null));
        assertEquals("31409299", OCRA.generateOCRA(suite, KEY_64, "00009", qHex("99999999"), null, null, null));
        
        suite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
        
        assertEquals("95209754", OCRA.generateOCRA(suite, KEY_64, null, qHex("00000000"), null, null, "132d0b6"));
        assertEquals("55907591", OCRA.generateOCRA(suite, KEY_64, null, qHex("11111111"), null, null, "132d0b6"));
        assertEquals("22048402", OCRA.generateOCRA(suite, KEY_64, null, qHex("22222222"), null, null, "132d0b6"));
        assertEquals("24218844", OCRA.generateOCRA(suite, KEY_64, null, qHex("33333333"), null, null, "132d0b6"));
        assertEquals("36209546", OCRA.generateOCRA(suite, KEY_64, null, qHex("44444444"), null, null, "132d0b6"));
    }

}
