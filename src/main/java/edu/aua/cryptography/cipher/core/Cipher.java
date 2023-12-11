package edu.aua.cryptography.cipher.core;

import java.math.BigInteger;

public interface Cipher {
    byte[] apply(OpMode opMode, byte[] message, byte[] publicKey, byte[] privateKey);

    enum OpMode {
        ENCRYPT, DECRYPT;
    }
}
