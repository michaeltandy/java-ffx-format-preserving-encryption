package uk.me.mjt.ffx;

import javax.xml.bind.DatatypeConverter;
import org.junit.Test;
import static org.junit.Assert.*;

public class FFXTest {

    public FFXTest() {
    }

    @Test
    public void testFk() {
        System.out.println("Fk");
        // Round 0 of test vector 2 from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/aes-ffx-vectors.txt
        int n = 10;
        byte[] T = {};
        int i = 0;
        long B = 56789;
        byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");
        FFX instance = new FFX();
        long expResult = 60536L;
        long result = instance.Fk(n, T, i, B, aesKey);
        assertEquals(expResult, result);
    }

    @Test
    public void testNumToBytes() {
        System.out.println("numToBytes");
        
        byte[] exp = {0, 100};
        assertArrayEquals(exp, FFX.numToBytes(100, 2));
        
        assertEquals(10000, FFX.bytesToLong(FFX.numToBytes(10000, 8)));
        assertEquals(10000, FFX.bytesToLong(FFX.numToBytes(10000, 4)));
    }
    
    @Test
    public void testConcatArrays() {
        System.out.println("concatArrays");
        byte[] a = {1, 2};
        byte[] b = {3, 4};
        byte[] c = {5};
        
        byte[] expResult = {1, 2, 3, 4, 5};
        
        byte[] result = FFX.concatArrays(a, b, c);
        assertArrayEquals(expResult, result);
    }
}