package edu.aua.cryptography.cipher.impl.symmetric;

import edu.aua.cryptography.cipher.core.Cipher;

public class AESCipher implements Cipher {
    private final int keyBitLength;

    public AESCipher(final int keyBitLength) {
        this.keyBitLength = keyBitLength;
    }

    @Override
    public byte[] apply(OpMode opMode, byte[] message) {
        return new byte[0];
    }
}
