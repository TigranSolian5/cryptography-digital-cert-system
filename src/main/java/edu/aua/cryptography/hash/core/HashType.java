package edu.aua.cryptography.hash.core;

import edu.aua.cryptography.hash.impl.Sha256Hash;

public enum HashType {
    SHA_256(new Sha256Hash());

    private final Hash hash;

    HashType(final Hash hash) {
        this.hash = hash;
    }

    public Hash getHash() {
        return hash;
    }
}
