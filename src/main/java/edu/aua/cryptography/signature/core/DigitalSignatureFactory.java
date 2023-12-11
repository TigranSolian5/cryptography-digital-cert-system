package edu.aua.cryptography.signature.core;

public class DigitalSignatureFactory {
    public DigitalSignature getSignature(final String signatureType) {
        return DigitalSignatureType.valueOf(signatureType).getSignature();
    }
}
