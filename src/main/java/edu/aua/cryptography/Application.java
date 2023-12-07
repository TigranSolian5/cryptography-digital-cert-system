package edu.aua.cryptography;

import edu.aua.cryptography.cipher.core.CipherFactory;
import edu.aua.cryptography.cipher.core.CipherType;

public class Application {
    public static void main(String[] args) {
        var cipherFactory = new CipherFactory();
        var AESCipher = cipherFactory.getInstance(CipherType.AES_256);
    }
}
