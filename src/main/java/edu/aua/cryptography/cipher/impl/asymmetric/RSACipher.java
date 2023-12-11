package edu.aua.cryptography.cipher.impl.asymmetric;

import java.math.BigInteger;
import edu.aua.cryptography.cipher.core.Cipher;

public class RSACipher implements Cipher {

    @Override
    public byte[] apply(OpMode opMode, byte[] message, byte[] publicKey, byte[] privateKey) {
        int componentLength = publicKey.length / 2;

        byte[] eBytes = new byte[componentLength];
        byte[] dBytes = new byte[componentLength];
        byte[] nBytes = new byte[componentLength];

        System.arraycopy(publicKey, 0, eBytes, 0, componentLength);
        System.arraycopy(privateKey, 0, dBytes, 0, componentLength);
        System.arraycopy(publicKey, componentLength, nBytes, 0, componentLength);

        BigInteger e = new BigInteger(1, eBytes);
        BigInteger d = new BigInteger(1, dBytes);
        BigInteger n = new BigInteger(1, nBytes);

        // Encryption / Decryption example
        BigInteger inputMessage = new BigInteger(message);
        BigInteger processedMessage = (opMode == OpMode.ENCRYPT) ? encrypt(inputMessage, e, n) : decrypt(inputMessage, d, n);

        // Convert processed message back to a string using UTF-8 encoding
        return processedMessage.toByteArray();
    }

    public static BigInteger encrypt(BigInteger message, BigInteger e, BigInteger n) {
        return message.modPow(e, n);
    }

    public static BigInteger decrypt(BigInteger message, BigInteger d, BigInteger n) {
        return message.modPow(d, n);
    }

    public static BigInteger getPhi(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }
}
