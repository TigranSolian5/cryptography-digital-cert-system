package edu.aua.cryptography.cipher.impl.symmetric;

import edu.aua.cryptography.cipher.core.Cipher;

import java.math.BigInteger;

public class AESCipher implements Cipher {
    private final int keyBitLength;

    public AESCipher(final int keyBitLength) {
        this.keyBitLength = keyBitLength;
    }

    @Override
    public String apply(OpMode opMode, String message, BigInteger publicKey, BigInteger privateKey) {
        // Implement AES encryption or decryption here
        return "";  // Placeholder, replace with actual implementation
    }
}
