package com.jessecoyle;

import org.hamcrest.Matchers;
import org.junit.Assume;
import org.junit.ClassRule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

/**
 * Created by jcoyle on 2/1/16.
 */
public class JavaxCryptoTest extends CredStashCryptoTest {

    @ClassRule
    public static TestRule assumption = new TestRule() {
        @Override
        public Statement apply(Statement statement, Description description) {
            try {
                int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength("AES");
                Assume.assumeThat("Unlimited Strength policy files installed", maxAllowedKeyLength, Matchers.greaterThanOrEqualTo(256));
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }

            return statement;
        }
    };

    public JavaxCryptoTest(String key, String decrypted, String encrypted) {
        super(key, decrypted, encrypted);
    }

    @Override
    protected CredStashCrypto getCryptoImplementation() {
        return new CredStashJavaxCrypto();
    }
}
