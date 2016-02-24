package com.jessecoyle;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Created by jcoyle on 2/1/16.
 */
public class CredStashBouncyCastleCrypto implements CredStashCrypto {
    @Override
    public byte[] decrypt(byte[] key, byte[] contents) {

        // Credstash uses standard AES
        BlockCipher engine = new AESFastEngine();

        // Credstash uses CTR mode
        StreamBlockCipher cipher = new SICBlockCipher(engine);

        boolean forEncryption = false;
        cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(key), INITIALIZATION_VECTOR));

        byte[] resultBytes = new byte[contents.length];
        int contentsOffset = 0;
        int resultOffset = 0;
        cipher.processBytes(contents, contentsOffset, contents.length, resultBytes, resultOffset);
        return resultBytes;
    }

    @Override
    public byte[] digest(byte[] key, byte[] contents) {
        // Credstash uses SHA-256
        SHA256Digest digest = new SHA256Digest();

        // Credstash uses HMAC
        HMac mac = new HMac(digest);

        byte[] resultBytes = new byte[mac.getMacSize()];

        mac.init(new KeyParameter(key));
        mac.update(contents, 0, contents.length);
        mac.doFinal(resultBytes, 0);

        return resultBytes;
    }
}
