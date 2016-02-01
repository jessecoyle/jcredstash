package com.jessecoyle;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.model.*;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.HashMap;
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

    protected static class StoredSecret {
        protected String key;
        protected String contents;

        public StoredSecret(String key, String contents) {
            this.key = key;
            this.contents = contents;
        }

        public String getKey() {
            return key;
        }

        public String getContents() {
            return contents;
        }
    }

    protected StoredSecret readDynamoItem(String secret) {
        // TODO: allow customization of table name
        // TODO: allow multiple secrets to be fetched by pattern or list
        QueryResult queryResult = amazonDynamoDBClient.query(new QueryRequest("credential-store")
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

        return new StoredSecret(item.get("key").getS(), item.get("contents").getS());
    }

    protected ByteBuffer decryptKeyWithKMS(String encryptedKey, Map<String, String> context) {
        ByteBuffer blob = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedKey));

        DecryptResult decryptResult = awskmsClient.decrypt(new DecryptRequest().withCiphertextBlob(blob).withEncryptionContext(context));

        return decryptResult.getPlaintext();
    }

    public String getSecret(String secret, Map<String, String> context)  {

        // The secret was encrypted using AES, then the key for that encryption was encrypted with AWS KMS
        // Then both the encrypted secret and the encrypted key are stored in dynamo

        // First find the relevant rows from the credstash table
        StoredSecret encrypted = readDynamoItem(secret);

        // First obtain that original key again using KMS
        ByteBuffer plainText = decryptKeyWithKMS(encrypted.getKey(), context);

        // The key is just the first 32 bits, the remaining are for HMAC signature checking
        byte[] keyBytes = new byte[32];
        plainText.get(keyBytes);

        //TODO check HMAC

        // now use AES to finally decrypt the actual secret
        byte[] contentBytes = Base64.getDecoder().decode(encrypted.getContents());
        byte[] decryptedBytes = cryptoImpl.decrypt(keyBytes, contentBytes);
        return new String(decryptedBytes);
    }
}
