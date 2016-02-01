package com.jessecoyle;

/**
 * Created by jcoyle on 2/1/16.
 */
public class BouncyCastleCryptoTest extends CredStashCryptoTest {
    public BouncyCastleCryptoTest(String key, String decrypted, String encrypted) {
        super(key, decrypted, encrypted);
    }

    @Override
    protected CredStashCrypto getCryptoImplementation() {
        return new CredStashBouncyCastleCrypto();
    }
}
