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
    @Parameterized.Parameters(name = "{0}({1}) = {2}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAA==", "Uw+K+w=="}
        });
    }

    private String key;
    private String encrypted;
    private String decrypted;

    public CredStashCryptoTest(String key, String decrypted, String encrypted) {
        this.key = key;
        this.decrypted = decrypted;
        this.encrypted = encrypted;
    }

    protected abstract CredStashCrypto getCryptoImplementation();


    @Test
    public void testDecrypt() throws Exception {
        byte[] keyBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(key);
        byte[] decryptedBytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(decrypted);
        byte[] encryptedbytes = javax.xml.bind.DatatypeConverter.parseBase64Binary(encrypted);

        CredStashCrypto crypto = getCryptoImplementation();

        byte[] actualDecrypted = crypto.decrypt(keyBytes, encryptedbytes);

        assertThat("Decrypted: " + javax.xml.bind.DatatypeConverter.printBase64Binary(actualDecrypted), actualDecrypted, equalTo(decryptedBytes));
    }
}