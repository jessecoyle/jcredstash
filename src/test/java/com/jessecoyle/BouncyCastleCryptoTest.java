package com.jessecoyle;

/**
 * Created by jcoyle on 2/1/16.
 */
public class BouncyCastleCryptoTest extends CredStashCryptoTest {
    public BouncyCastleCryptoTest(String name, String key, String digestKey, String decrypted, String encrypted, String digest) {
        super(name, key, digestKey, decrypted, encrypted, digest);
    }

    @Override
    protected CredStashCrypto getCryptoImplementation() {
        return new CredStashBouncyCastleCrypto();
    }
}
