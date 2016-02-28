
package uk.me.mjt.ffx;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class FFX {
    private final byte VERSION_ONE = 1;
    private final byte ADDITION_BLOCKWISE = 1;
    private final byte METHOD_ALTERNATING_FEISTEL = 2;
    private final byte RADIX_TEN = 10;
    private final byte ROUNDS_TEN = 10;
    
    long Fk(int n, byte[] T, int i, long B, byte[] aesKey) {
        int t = T.length;
        int β = (n+1)/2;
        int b = (int)((Math.ceil(β * Math.log(β)/Math.log(2))+7)/8);
        int d = 4*((b+3)/4);
        
        int m = (i%2==0 ? n/2 : (n+1)/2);
        
        byte splitN = (byte)((n/2)&0xFF);
        byte[] P = {
            VERSION_ONE,
            METHOD_ALTERNATING_FEISTEL,
            ADDITION_BLOCKWISE,
            0,0,RADIX_TEN,
            ROUNDS_TEN,
            splitN,
            (byte)(n>>24&0xFF), (byte)(n>>16&0xFF), (byte)(n>>8&0xFF), (byte)(n>>0&0xFF),
            (byte)(t>>24&0xFF), (byte)(t>>16&0xFF), (byte)(t>>8&0xFF), (byte)(t>>0&0xFF)
        };
        
        int paddingLength = (-t-b-1) & 0x0F;
        
        byte[] Q = concatArrays(T,
                new byte[paddingLength],
                numToBytes(i, 1),
                numToBytes(B, b));
        
        byte[] toEncrypt = concatArrays(P, Q);
        byte[] Y = aesCbcMac(toEncrypt, aesKey);
        
        if (Y.length < d+4) {
            throw new RuntimeException("Michael hasn't done this yet.");
        }
        
        BigInteger y = bytesToBiginteger(Arrays.copyOf(Y, d+4));
        
        BigInteger divisor = BigInteger.TEN.pow(m);
        BigInteger z = y.mod(divisor);
        
        return z.longValueExact();
    }
    
    static byte[] aesCbcMac(byte[] toEncrypt, byte[] aesKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec key = new SecretKeySpec(aesKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            byte[] encrypted = cipher.doFinal(toEncrypt);
            return Arrays.copyOfRange(encrypted, encrypted.length-16, encrypted.length);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("This should never happen?",e);
        }
    }
    
    static byte[] numToBytes(long num, int byteCount) {
        byte[] result = new byte[byteCount];
        for (int i=0 ; i<byteCount ; i++) {
            long thisVal = num&0xFF;
            num = num>>8;
            result[byteCount-1-i] = (byte)(thisVal);
        }
        return result;
    }
    
    static BigInteger bytesToBiginteger(byte[] bytes) {
        byte[] leadingZero = new byte[bytes.length+1];
        System.arraycopy(bytes,0,leadingZero,1,bytes.length);
        return new BigInteger(leadingZero);
    }
    
    static long bytesToLong(byte[] bytes) {
        long result = 0;
        for (int i=0 ; i<bytes.length ; i++) {
            result = (result<<8)|bytes[i];
        }
        return result;
    }
    
    static byte[] concatArrays(byte[] ... inputs) {
        byte[] result = inputs[0];
        for (int i=1 ; i<inputs.length ; i++) {
            result = concatTwoArrays(result, inputs[i]);
        }
        return result;
    }
    
    static byte[] concatTwoArrays(byte[] a, byte[] b) {
        byte[] copy = Arrays.copyOf(a, a.length+b.length);
        System.arraycopy(b,0,copy,a.length,b.length);
        return copy;
    }

}
