package edu.aua.cryptography.signature.core;

public class DigitalSignatureFactory {
    public DigitalSignature getSignature(final DigitalSignatureType signatureType) {
        return signatureType.getSignature();
    }
}
