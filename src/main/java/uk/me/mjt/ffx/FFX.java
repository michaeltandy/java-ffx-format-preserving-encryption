
package uk.me.mjt.ffx;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class FFX {
    private final byte VERSION_ONE = 1;
    private final byte ADDITION_BLOCKWISE = 1;
    private final byte METHOD_ALTERNATING_FEISTEL = 2;
    private final byte RADIX_TEN = 10;
    private final byte ROUNDS_TEN = 10;
    
    BigInteger encrypt(byte[] aesKey, byte[] T, BigInteger X, int n, StringBuilder log) {
        int l = (n+1)/2;
        BigInteger bMagnitude = BigInteger.TEN.pow(l);
        BigInteger aMagnitude = BigInteger.TEN.pow(n-l);
        
        BigInteger[] split = X.divideAndRemainder(bMagnitude);
        
        BigInteger A = split[0];
        BigInteger B = split[1];
        
        int resultOffset = 0;
        if (log != null) {
            log.append(String.format("  Input (length = %d): \"%s\"\n\n", n, digits(X,n)));
            if (T.length==0) {
                log.append("  No Tweak\n\n\n\n");
            } else {
                log.append(String.format("  Tweak (length = %d): \"%s\"\n\n\n\n", T.length, new String(T)));
            }
            resultOffset = log.length();
            log.append("  Intermediate values:\n\n\n\n");
        }
        
        for (int i=0 ; i<ROUNDS_TEN ; i++) {
            BigInteger C = A.add(Fk(n, T, i, B, aesKey, log)).mod(aMagnitude);
            BigInteger cMagnitude = aMagnitude;
            A = B;
            aMagnitude = bMagnitude;
            B = C;
            bMagnitude = cMagnitude;
            if (log != null) {
                log.append("    L = ").append(digits(A, l)).append(", R = ").append(digits(B, l)).append("\n\n\n\n");
            }
        }
        
        BigInteger encrypted = A.multiply(bMagnitude).add(B);
        
        if (log != null) {
            log.insert(resultOffset, "  Encrypted: \""+encrypted+"\"\n\n\n\n");
        }
        
        return encrypted;
    }
    
    BigInteger Fk(int n, byte[] T, int i, BigInteger B, byte[] aesKey, StringBuilder log) {
        int t = T.length;
        int β = (n+1)/2;
        int b = (int)((Math.ceil(β * Math.log(RADIX_TEN)/Math.log(2))+7)/8);
        int d = 4*((b+3)/4);
        
        int m = (i%2==0 ? n/2 : (n+1)/2);
        
        byte[] P = generateP(n, t);
        
        int tPaddingLength = (-t-b-1) & 0x0F;
        byte[] Bbytes = B.toByteArray();
        if (Bbytes.length > b) {
            throw new RuntimeException("Michael didn't expect B longer than " + b);
        }
        int bPaddingLength = b-Bbytes.length;
        
        byte[] Q = concatArrays(T,
                new byte[tPaddingLength],
                numToBytes(i, 1),
                new byte[bPaddingLength],
                Bbytes);
        
        byte[] toEncrypt = concatArrays(P, Q);
        byte[] cbcMac = aesCbcMac(toEncrypt, aesKey);
        byte[] Y = cbcMac;
        
        if (Y.length < d+4) {
            throw new RuntimeException("Michael hasn't done this yet.");
        }
        
        BigInteger y = bytesToBiginteger(Arrays.copyOf(Y, d+4));
        
        BigInteger divisor = BigInteger.TEN.pow(m);
        BigInteger z = y.mod(divisor);
        
        if (log != null) {
            log.append("  Round ").append(i).append(":\n\n");
            log.append("    B_").append(i).append(" = ").append(B).append("\n\n");
            log.append("    Q = ").append(arrayToString(Q)).append("\n\n");
            log.append("    CBC-MAC = ").append(arrayToString(cbcMac)).append("\n\n");
            log.append("    F_out = ").append(digits(z,m)).append("\n\n");
        }
        
        return z;
    }
    
    private byte[] generateP(int n, int t) {
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
        return P;
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
    
    static String arrayToString(byte[] input) {
        return "[ " + IntStream.range(0, input.length)
                .mapToObj(i -> ""+(input[i]&0xFF))
                .collect(Collectors.joining(", ")) + " ]";
    }
    
    static String digits(BigInteger integer, int digits) {
        return String.format("%0"+digits+"d", integer);
    }

}
