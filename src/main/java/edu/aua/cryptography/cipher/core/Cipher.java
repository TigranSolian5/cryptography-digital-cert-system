package edu.aua.cryptography.cipher.core;

import java.math.BigInteger;

public interface Cipher {
    String apply(OpMode opMode, String message, BigInteger publicKey, BigInteger privateKey);

    enum OpMode {
        ENCRYPT, DECRYPT;
    }
}
