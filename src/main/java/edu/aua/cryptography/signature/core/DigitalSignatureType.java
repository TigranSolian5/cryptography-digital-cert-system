package edu.aua.cryptography.signature.core;

import edu.aua.cryptography.signature.impl.ElGamalSignature;

public enum DigitalSignatureType {
    ELGAMAL(new ElGamalSignature());

    private final DigitalSignature signature;

    DigitalSignatureType(final DigitalSignature signature) {
        this.signature = signature;
    }

    public DigitalSignature getSignature() {
        return signature;
    }
}
