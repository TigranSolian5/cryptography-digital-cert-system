package edu.aua.cryptography.cipher.impl.asymmetric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import edu.aua.cryptography.cipher.core.Cipher;

public class RSACipher implements Cipher {

    @Override
    public String apply(OpMode opMode, String message, BigInteger publicKey, BigInteger privateKey) {
        int length = 1024;
        BigInteger p = generateLargePrime(length);
        BigInteger q = generateLargePrime(length);

        BigInteger n = n(p, q);

        // Encryption / Decryption example
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        BigInteger inputMessage = new BigInteger(messageBytes);
        BigInteger processedMessage = (opMode == OpMode.ENCRYPT) ? encrypt(inputMessage, publicKey, n) : decrypt(inputMessage, privateKey, n);

        // Convert processed message back to a string using UTF-8 encoding
        String resultMessage = new String(processedMessage.toByteArray(), StandardCharsets.UTF_8);

        return resultMessage;
    }

    public static void printGeneratedValues(BigInteger p, BigInteger q, BigInteger n, BigInteger phi, BigInteger e, BigInteger d) {
        System.out.println("p: " + p);
        System.out.println("q: " + q);
        System.out.println("n: " + n);
        System.out.println("Phi: " + phi);
        System.out.println("e: " + e);
        System.out.println("d: " + d);
    }

    public static void printResults(String message, BigInteger cipherMessage, BigInteger encrypted, BigInteger decrypted, String restoredMessage) {
        System.out.println("Original message: " + message);
        System.out.println("Ciphered: " + cipherMessage);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
        System.out.println("Restored: " + restoredMessage);
    }

    public static BigInteger stringToBigInteger(String message) {
        return new BigInteger(message.getBytes(StandardCharsets.UTF_8));
    }

    public static String bigIntegerToString(BigInteger message) {
        return new String(message.toByteArray(), StandardCharsets.UTF_8);
    }

    public static BigInteger generateLargePrime(int bits) {
        return BigInteger.probablePrime(bits, new SecureRandom());
    }

    public static BigInteger generatePublicKey(BigInteger phi) {
        BigInteger e;
        do {
            e = BigInteger.probablePrime(phi.bitLength() - 1, new SecureRandom());
        } while (!gcd(e, phi).equals(BigInteger.ONE));
        return e;
    }

    public static BigInteger calculatePrivateKey(BigInteger e, BigInteger phi) {
        return e.modInverse(phi);
    }

    public static BigInteger n(BigInteger p, BigInteger q) {
        return p.multiply(q);
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
