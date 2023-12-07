package edu.aua.cryptography.cipher.core;

public interface Cipher {
    byte[] apply(final OpMode opMode, final byte[] message);

    enum OpMode {
        ENCRYPT, DECRYPT;
    }
}
