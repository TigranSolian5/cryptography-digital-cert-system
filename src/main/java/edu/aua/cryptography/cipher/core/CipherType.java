package edu.aua.cryptography.cipher.core;

import edu.aua.cryptography.cipher.impl.asymmetric.RSACipher;
import edu.aua.cryptography.cipher.impl.symmetric.AESCipher;

public enum CipherType {
    AES_256(new AESCipher(256)),
    RSA(new RSACipher());

    private final Cipher cipherInstance;

    CipherType(final Cipher cipherInstance) {
        this.cipherInstance = cipherInstance;
    }

    public Cipher getCipherInstance() {
        return cipherInstance;
    }
}
