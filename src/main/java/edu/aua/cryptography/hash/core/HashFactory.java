package edu.aua.cryptography.hash.core;

public class HashFactory {
    public Hash getHash(final HashType hashType) {
        return hashType.getHash();
    }
}
