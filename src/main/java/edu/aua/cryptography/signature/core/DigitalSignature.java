package edu.aua.cryptography.signature.core;

public interface DigitalSignature {
    byte[] sign(final byte[] message, final byte[] publicKey, final byte[] privateKey);
    boolean validate(final byte[] signature, final byte[] publicKey,final byte[] message);
}