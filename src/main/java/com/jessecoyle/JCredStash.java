package com.jessecoyle;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.model.*;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * Created by jcoyle on 2/1/16.
 */
public class JCredStash {
    protected AmazonDynamoDBClient amazonDynamoDBClient;
    protected AWSKMSClient awskmsClient;
    protected CredStashCrypto cryptoImpl;

    public JCredStash() {
        this.amazonDynamoDBClient = new AmazonDynamoDBClient();
        this.awskmsClient = new AWSKMSClient();
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    public JCredStash(AWSCredentialsProvider awsCredentialsProvider) {
        this.amazonDynamoDBClient = new AmazonDynamoDBClient(awsCredentialsProvider);
        this.awskmsClient = new AWSKMSClient(awsCredentialsProvider);
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    public JCredStash(AmazonDynamoDBClient amazonDynamoDBClient, AWSKMSClient awskmsClient) {
        this.amazonDynamoDBClient = amazonDynamoDBClient;
        this.awskmsClient = awskmsClient;
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    /**
     * Represents a row in a credstash table. The encrypted key and encrypted contents are both stored base64 encoded.
     * The hmac digest is stored hex encoded.
     */
    protected static class StoredSecret {
        protected byte[] key;
        protected byte[] contents;
        protected byte[] hmac;

        protected static byte[] base64AttributeValueToBytes(AttributeValue value) {
            return Base64.getDecoder().decode(value.getS());
        }

        protected static byte[] hexAttributeValueToBytes(AttributeValue value) {
            try {
                return Hex.decodeHex(value.getS().toCharArray());
            } catch (DecoderException e) {
                throw new RuntimeException(e);
            }
        }

        public StoredSecret(Map<String, AttributeValue> item) {
            this.key = base64AttributeValueToBytes(item.get("key"));
            this.contents = base64AttributeValueToBytes(item.get("contents"));
            this.hmac = hexAttributeValueToBytes(item.get("hmac"));
        }

        public byte[] getKey() {
            return key;
        }

        public byte[] getContents() {
            return contents;
        }

        public byte[] getHmac() {
            return hmac;
        }
    }

    protected StoredSecret readDynamoItem(String tableName, String secret) {
        // TODO: allow multiple secrets to be fetched by pattern or list
        // TODO: allow specific version to be fetched
        QueryResult queryResult = amazonDynamoDBClient.query(new QueryRequest(tableName)
                .withLimit(1)
                .withScanIndexForward(false)
                .withConsistentRead(true)
                .addKeyConditionsEntry("name", new Condition()
                        .withComparisonOperator(ComparisonOperator.EQ)
                        .withAttributeValueList(new AttributeValue(secret)))
        );
        if(queryResult.getCount() == 0) {
            throw new RuntimeException("Secret " + secret + " could not be found");
        }
        Map<String, AttributeValue> item = queryResult.getItems().get(0);

        return new StoredSecret(item);
    }

    protected ByteBuffer decryptKeyWithKMS(byte[] encryptedKeyBytes, Map<String, String> context) {
        ByteBuffer blob = ByteBuffer.wrap(encryptedKeyBytes);

        DecryptResult decryptResult = awskmsClient.decrypt(new DecryptRequest().withCiphertextBlob(blob).withEncryptionContext(context));

        return decryptResult.getPlaintext();
    }

    // default table name: "credential-store"
    public String getSecret(String tableName, String secret, Map<String, String> context)  {

        // The secret was encrypted using AES, then the key for that encryption was encrypted with AWS KMS
        // Then both the encrypted secret and the encrypted key are stored in dynamo

        // First find the relevant rows from the credstash table
        StoredSecret encrypted = readDynamoItem(tableName, secret);

        // First obtain that original key again using KMS
        ByteBuffer plainText = decryptKeyWithKMS(encrypted.getKey(), context);

        // The key is just the first 32 bits, the remaining are for HMAC signature checking
        byte[] keyBytes = new byte[32];
        plainText.get(keyBytes);

        byte[] hmacKeyBytes = new byte[plainText.remaining()];
        plainText.get(hmacKeyBytes);
        byte[] digest = cryptoImpl.digest(hmacKeyBytes, encrypted.getContents());
        if(!Arrays.equals(digest, encrypted.getHmac())) {
            throw new RuntimeException("HMAC integrety check failed"); //TODO custom exception type
        }

        // now use AES to finally decrypt the actual secret
        byte[] decryptedBytes = cryptoImpl.decrypt(keyBytes, encrypted.getContents());
        return new String(decryptedBytes);
    }
}
