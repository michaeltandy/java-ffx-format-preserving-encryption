package uk.me.mjt.ffx;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

public class FFXTest {

    public FFXTest() {
    }

    @Test
    public void testFk() {
        // Round 0 of test vector 2 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
        int n = 10;
        byte[] T = {};
        int i = 0;
        BigInteger B = BigInteger.valueOf(56789);
        byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
        FFX instance = new FFX();
        BigInteger expResult = BigInteger.valueOf(60536);
        BigInteger result = instance.Fk(n, T, i, B, aesKey, null);
        assertEquals(expResult, result);
    }
    
    @Test
    public void testFk2() {
        // Round 4 of test vector 2 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
        int n = 10;
        byte[] T = {};
        int i = 4;
        BigInteger B = BigInteger.valueOf(94407);
        byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
        FFX instance = new FFX();
        BigInteger expResult = BigInteger.valueOf(87727);
        BigInteger result = instance.Fk(n, T, i, B, aesKey, null);
        assertEquals(expResult, result);
    }
    
    @Test
    public void testEncrypt1() throws UnsupportedEncodingException {
        // Test vector 1 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
        byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] T = "9876543210".getBytes("UTF-8");
        BigInteger X = BigInteger.valueOf(123456789L);
        int n = 10;
        
        BigInteger expResult = BigInteger.valueOf(6124200773L);
        
        FFX instance = new FFX();
        StringBuilder log = new StringBuilder();
        BigInteger result = instance.encrypt(aesKey, T, X, n, log);
        
        System.out.println(log);
        assertEquals(expResult, result);
    }
    
    @Test
    public void testEncrypt2() {
        // Test vector 2 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
        byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] T = {};
        BigInteger X = BigInteger.valueOf(123456789L);
        int n = 10;
        
        BigInteger expResult = BigInteger.valueOf(2433477484L);
        
        FFX instance = new FFX();
        StringBuilder log = new StringBuilder();
        BigInteger result = instance.encrypt(aesKey, T, X, n, log);
        
        System.out.println(log);
        assertEquals(expResult, result);
    }
    
    @Test
    public void testEncrypt3() throws UnsupportedEncodingException {
        // Test vector 3 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
        byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] T = "2718281828".getBytes("UTF-8");
        BigInteger X = BigInteger.valueOf(314159L);
        int n = 6;
        
        BigInteger expResult = BigInteger.valueOf(535005L);
        
        FFX instance = new FFX();
        StringBuilder log = new StringBuilder();
        BigInteger result = instance.encrypt(aesKey, T, X, n, log);
        
        System.out.println(log);
        assertEquals(expResult, result);
    }
    
    @Test
    public void testEncrypt4() throws UnsupportedEncodingException {
        // Test vector 4 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
        byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] T = "7777777".getBytes("UTF-8");
        BigInteger X = BigInteger.valueOf(999999999L);
        int n = 9;
        
        BigInteger expResult = BigInteger.valueOf(658229573L);
        
        FFX instance = new FFX();
        StringBuilder log = new StringBuilder();
        BigInteger result = instance.encrypt(aesKey, T, X, n, log);
        
        System.out.println(log);
        assertEquals(expResult, result);
    }

    @Test
    public void testNumToBytes() {
        byte[] exp = {0, 100};
        assertArrayEquals(exp, FFX.numToBytes(100, 2));
        
        assertEquals(10000, FFX.bytesToLong(FFX.numToBytes(10000, 8)));
        assertEquals(10000, FFX.bytesToLong(FFX.numToBytes(10000, 4)));
    }
    
    @Test
    public void testConcatArrays() {
        byte[] a = {1, 2};
        byte[] b = {3, 4};
        byte[] c = {5};
        
        byte[] expResult = {1, 2, 3, 4, 5};
        
        byte[] result = FFX.concatArrays(a, b, c);
        assertArrayEquals(expResult, result);
    }
}