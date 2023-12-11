package edu.aua.cryptography.signature.impl;

import edu.aua.cryptography.signature.core.DigitalSignature;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class ElGamalSignature implements DigitalSignature {
    @Override
    public byte[] sign(byte[] message, byte[] publicKey, byte[] privateKey) {
        /*
        1. Key Generation: A user generates a public key and a private key. The public key consists of the values p, g, and y, where p is a large prime number, g is a generator of the multiplicative group modulo p, and y = g^x mod p, where x is the private key.
        2. Signing: To sign a message M, the signer performs the following steps:

        a. Generate a random number k such that 1 < k < p-1.
        b. Calculate r = g^k mod p.
        c. Calculate h = hash(M), where hash is a fixed-size hash function.
        d. Calculate s = (h — xr) * k^-1 mod (p-1).
        e. The signature of the message M is the pair (r, s).
        */
        int componentLength = publicKey.length / 3;

        byte[] pBytes = new byte[componentLength];
        byte[] gBytes = new byte[componentLength];
        byte[] yBytes = new byte[componentLength];

        System.arraycopy(publicKey, 0, pBytes, 0, componentLength);
        System.arraycopy(publicKey, componentLength, gBytes, 0, componentLength);
        System.arraycopy(publicKey, 2 * componentLength, yBytes, 0, componentLength);

        BigInteger p = new BigInteger(1, pBytes);
        BigInteger g = new BigInteger(1, gBytes);
        BigInteger y = new BigInteger(1, yBytes);

        BigInteger x = new BigInteger(1,privateKey);

        SecureRandom random = new SecureRandom();
        BigInteger k;

        do {
            k = new BigInteger(p.bitLength(), random);
        } while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(p.subtract(BigInteger.ONE)) >= 0);

        BigInteger r = g.modPow(k, p);
        // Calculate s = (k^-1 * (hash(message) - x * r) mod (p-1))

        MessageDigest sha256Digest;
        try {
            sha256Digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
        sha256Digest.update(message);
        byte[] hashedMessage = sha256Digest.digest();
        BigInteger hashMessage = new BigInteger(1, hashedMessage);

        BigInteger xTimesR = x.multiply(r);
        BigInteger hashMinusXTimesR = hashMessage.subtract(xTimesR);
        BigInteger kInverse = k.modInverse(p.subtract(BigInteger.ONE));
        BigInteger s = kInverse.multiply(hashMinusXTimesR).mod(p.subtract(BigInteger.ONE));

        // Return the signature as byte array
        byte[] rBytes = truncateOrPadTo4Bytes(r.toByteArray());
        byte[] sBytes = truncateOrPadTo4Bytes(s.toByteArray());

        // Return the signature as byte array
        byte[] signature = new byte[8];
        System.arraycopy(rBytes, 0, signature, 0, 4);
        System.arraycopy(sBytes, 0, signature, 4, 4);

        return signature;
    }


    /*
    3. Verifying: To verify the signature (r, s) of a message M, the verifier performs the following steps:

    a. Verify that 1 < r < p-1 and 0 < s < p-1. If either condition is not satisfied, the signature is invalid.
    b. Calculate h = hash(M).
    c. Calculate v1 = (y^r * r^s) mod p.
    d. Calculate v2 = g^h mod p.
    e. If v1 = v2, the signature is valid. Otherwise, the signature is invalid
    */

    public boolean validate(byte[] signature, byte[] publicKey, byte[] message) {
        int componentLength = publicKey.length / 3;
        System.out.println("componentLength: " + componentLength);

        byte[] pBytes = new byte[componentLength];
        byte[] gBytes = new byte[componentLength];
        byte[] yBytes = new byte[componentLength];

        System.arraycopy(publicKey, 0, pBytes, 0, componentLength);
        System.arraycopy(publicKey, componentLength, gBytes, 0, componentLength);
        System.arraycopy(publicKey, 2 * componentLength, yBytes, 0, componentLength);
        BigInteger p = new BigInteger(1, pBytes);
        BigInteger g = new BigInteger(1, gBytes);
        BigInteger y = new BigInteger(1, yBytes);

        // Extract r and s from the signature
        int signatureLength = signature.length / 2;

        byte[] rBytes = new byte[signatureLength];
        byte[] sBytes = new byte[signatureLength];
        System.arraycopy(signature, 0, rBytes, 0, Math.min(componentLength, signature.length));
        System.arraycopy(signature, componentLength, sBytes, 0, Math.min(componentLength, signature.length));

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        // Verify 0 < r < p and 0 < s < p-1
        if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(p) >= 0 || s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            return false;
        }

        // Calculate w = s^(-1) mod (p-1)
        BigInteger w = s.modInverse(p.subtract(BigInteger.ONE));

        MessageDigest sha256Digest;
        try {
            sha256Digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
        sha256Digest.update(message);
        byte[] hash = sha256Digest.digest();

        // Calculate u1 = (hash(message) * w) mod (p-1) and u2 = (r * w) mod (p-1)
        BigInteger hashMessage = new BigInteger(1, hash);
        BigInteger u1 = hashMessage.multiply(w).mod(p.subtract(BigInteger.ONE));
        BigInteger u2 = r.multiply(w).mod(p.subtract(BigInteger.ONE));

        // Calculate v = ((g^u1 * y^u2) mod p) mod (p-1)
        BigInteger gU1 = g.modPow(u1, p);
        BigInteger yU2 = y.modPow(u2, p);
        BigInteger v = gU1.multiply(yU2).mod(p).mod(p.subtract(BigInteger.ONE));

        return v.equals(r);
    }
    private byte[] truncateOrPadTo4Bytes(byte[] input) {
        if (input.length == 4) {
            return input;
        } else if (input.length < 4) {
            byte[] result = new byte[4];
            System.arraycopy(input, 0, result, 4 - Math.min(4, input.length), Math.min(4, input.length));
            return result;
        } else {
            return Arrays.copyOfRange(input, input.length - 4, input.length);
        }
    }

}