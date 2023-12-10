package edu.aua.cryptography.signature.impl;

import edu.aua.cryptography.signature.core.DigitalSignature;

public class ElGamalSignature implements DigitalSignature {
    @Override
    public byte[] sign(byte[] message, byte[] publicKey, byte[] privateKey) {
        return new byte[0];
    }

    @Override
    public byte[] validate(byte[] signature, byte[] publicKey) {
        return new byte[0];
    }
}
