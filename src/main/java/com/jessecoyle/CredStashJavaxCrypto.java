package com.jessecoyle;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by jcoyle on 2/1/16.
 */
public class CredStashJavaxCrypto implements CredStashCrypto {
    protected final String CIPHER_TRANSFORMATION = "AES/CTR/NoPadding";
    protected final String MAC_SERVICE = "HmacSHA256";
    protected Cipher cipher;
    protected IvParameterSpec ivParameterSpec;
    protected Mac mac;

    public CredStashJavaxCrypto() {
        try {
            int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            if(maxAllowedKeyLength < 256) {
                throw new RuntimeException("Maximum key length " + maxAllowedKeyLength + " too low, likely Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files not installed");
            }
            cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            ivParameterSpec = new IvParameterSpec(INITIALIZATION_VECTOR);
            mac = Mac.getInstance(MAC_SERVICE);
        } catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Error initializing javax.crypto", e);
        }
    }

    public byte[] decrypt(byte[] key, byte[] contents) {
        return encryptOrDecrypt(key, contents, false);
    }

    public byte[] encrypt(byte[] key, byte[] contents) {
        return encryptOrDecrypt(key, contents, true);
    }

    private byte[] encryptOrDecrypt(byte[] key, byte[] contents, boolean forEncryption) {
        SecretKeySpec aes = new SecretKeySpec(key, "AES");

        try {

            // Credstash initial value for the counter starts at 1 (the default for pycrypto) rather than 0 or
            // a randomly chosen value.  New randomly chosen values should always be used when the key is being reused
            // to prevent attackers from finding identically encrypted blocks and deducing the blocks to be identical
            // when unencrypted. In this case it's safe to reuse initial values because a new key is chosen for
            // every encrypted secret.
            cipher.init(forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, aes, ivParameterSpec);

            return cipher.doFinal(contents);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            throw new RuntimeException("Error executing javax.crypto", e);
        }
    }

    @Override
    public byte[] digest(byte[] keyBytes, byte[] contents) {
        SecretKeySpec hmac = new SecretKeySpec(keyBytes, "HmacSHA256");
        try {
            mac.init(hmac);
            return mac.doFinal(contents);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Error verifying javax.crypto", e);
        }
    }
}
