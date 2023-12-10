package edu.aua.cryptography.hash.core;

public interface Hash {
    byte[] apply(final byte[] message);
}
