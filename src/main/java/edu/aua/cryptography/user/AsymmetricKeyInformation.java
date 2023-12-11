package edu.aua.cryptography.user;

public class AsymmetricKeyInformation {
    private final byte[] publicKey;
    private byte[] privateKey;
    private final String algorithm;

    public AsymmetricKeyInformation(byte[] publicKey, byte[] privateKey, String algorithm) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.algorithm = algorithm;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }
}
