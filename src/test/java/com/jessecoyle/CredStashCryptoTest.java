package com.jessecoyle;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 * Created by jcoyle on 2/1/16.
 */
@RunWith(Parameterized.class)
public abstract class CredStashCryptoTest {
    @Parameterized.Parameters(name = "{index} {0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {
                        "Simple",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "AAAAAA==", "Uw+K+w==", "AA7855E13839DD767CD5DA7C1FF5036540C9264B7A803029315E55375287B4AF"
                }
        });
    }

    private String key;
    private String digestKey;
    private String encrypted;
    private String decrypted;
    private String digest;

    public CredStashCryptoTest(String name, String key, String digestKey, String decrypted, String encrypted, String digest) {
        this.key = key;
        this.digestKey = digestKey;
        this.decrypted = decrypted;
        this.encrypted = encrypted;
        this.digest = digest;
    }

    protected abstract CredStashCrypto getCryptoImplementation();


    @Test
    public void testDecrypt() throws Exception {
        byte[] keyBytes = javax.xml.bind.DatatypeConverter.parseHexBinary(key);
        byte[] decryptedBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(decrypted);
        byte[] encryptedbytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(encrypted);

        CredStashCrypto crypto = getCryptoImplementation();

        byte[] actualDecrypted = crypto.decrypt(keyBytes, encryptedbytes);

        assertThat("Decrypted: " + javax.xml.bind.DatatypeConverter.printBase64Binary(actualDecrypted), actualDecrypted, equalTo(decryptedBytes));
    }

    @Test
    public void testDigest() throws Exception {
        byte[] decryptedBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(decrypted);
        byte[] digestKeyBytes = javax.xml.bind.DatatypeConverter.parseHexBinary(digestKey);
        byte[] digestBytes = javax.xml.bind.DatatypeConverter.parseHexBinary(digest);

        CredStashCrypto crypto = getCryptoImplementation();

        byte[] actualDigest = crypto.digest(digestKeyBytes, decryptedBytes);

        assertThat("Digest: " + javax.xml.bind.DatatypeConverter.printHexBinary(actualDigest), actualDigest, equalTo(digestBytes));
    }
}