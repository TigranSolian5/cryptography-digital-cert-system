package edu.aua.cryptography.cipher.core;

public class CipherFactory {
    public Cipher getInstance(final CipherType cipher) {
        return cipher.getCipherInstance();
    }
}
