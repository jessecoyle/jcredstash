package com.jessecoyle;

/**
 * Created by jcoyle on 2/1/16.
 */
public interface CredStashCrypto {

    /**
     * Credstash initial value for the counter starts at 1 (the default for pycrypto) rather than 0 or
     * a randomly chosen value.  New randomly chosen values should always be used when the key is being reused
     * to prevent attackers from finding identically encrypted blocks and deducing the blocks to be identical
     * when unencrypted. In this case it's safe to reuse initial values because a new key is chosen for
     * every encrypted secret.
     */
    byte[] INITIALIZATION_VECTOR = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    byte[] decrypt(byte[] key, byte[] contents);

    byte[] encrypt(byte[] key, byte[] contents);

    byte[] digest(byte[] keyBytes, byte[] contents);
}
