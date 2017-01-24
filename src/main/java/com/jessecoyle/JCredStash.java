package com.jessecoyle;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ComparisonOperator;
import com.amazonaws.services.dynamodbv2.model.Condition;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.QueryResult;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.nio.ByteBuffer;
import java.util.Arrays;
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

    /**
     * Represents a row in a credstash table. The encrypted key and encrypted contents are both stored base64 encoded.
     * The hmac digest is stored hex encoded.
     */
    protected static class StoredSecret {
        protected byte[] key;
        protected byte[] contents;
        protected byte[] hmac;
        protected String version;

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
            this.version = item.get("version").getS();
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

        public String getVersion() {
            return version;
        }
    }

    protected StoredSecret readDynamoItem(String tableName, String secretName) {
        // TODO: allow multiple secrets to be fetched by pattern or list
        // TODO: allow specific version to be fetched
        QueryResult queryResult = amazonDynamoDBClient.query(new QueryRequest(tableName)
                .withLimit(1)
                .withScanIndexForward(false)
                .withConsistentRead(true)
                .addKeyConditionsEntry("name", new Condition()
                        .withComparisonOperator(ComparisonOperator.EQ)
                        .withAttributeValueList(new AttributeValue(secretName)))
        );
        if(queryResult.getCount() == 0) {
            return null;
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
    public String getSecret(String tableName, String secretName, Map<String, String> context)  {

        // The secret was encrypted using AES, then the key for that encryption was encrypted with AWS KMS
        // Then both the encrypted secret and the encrypted key are stored in dynamo

        // First find the relevant rows from the credstash table
        StoredSecret encrypted = readDynamoItem(tableName, secretName);
        if(encrypted == null) {
            throw new RuntimeException("Secret " + secretName + " could not be found");
        }

        // First obtain that original key again using KMS
        ByteBuffer plainText = decryptKeyWithKMS(encrypted.getKey(), context);

        // The key is just the first 32 bits, the remaining are for HMAC signature checking
        byte[] keyBytes = new byte[32];
        plainText.get(keyBytes);

        byte[] hmacKeyBytes = new byte[plainText.remaining()];
        plainText.get(hmacKeyBytes);
        byte[] digest = cryptoImpl.digest(hmacKeyBytes, encrypted.getContents());
        if(!Arrays.equals(digest, encrypted.getHmac())) {
            throw new RuntimeException("HMAC integrity check failed"); //TODO custom exception type
        }

        // now use AES to finally decrypt the actual secret
        byte[] decryptedBytes = cryptoImpl.decrypt(keyBytes, encrypted.getContents());
        return new String(decryptedBytes);
    }

    /**
     * Puts a secret into credstash with auto-versioning. Uses a 19 character padded integer as a version and
     * will auto-increment each time a secret is stashed.
     *
     * @param tableName Credstash DynamoDB table name
     * @param secretName Credstash secret name
     * @param secret The secret value
     * @param kmsKeyId The KMS KeyId used to generate a new data key
     * @param context Encryption context for integrity check
     *
     * @throws NumberFormatException If the currently stashed secrets highest version can't be parsed to an integer
     */
    public void putSecret(String tableName, String secretName, String secret, String kmsKeyId, Map<String, String> context) {
        String version = getHighestVersion(tableName, secretName);
        if(version != null)
        {
            int v = Integer.parseInt(version);
            version = padVersion(v + 1);
        }
        putSecret(tableName, secretName, secret, kmsKeyId, context, version);
    }

    /**
     * Puts a secret into credstash with a specified version.
     *
     * @param tableName Credstash DynamoDB table name
     * @param secretName Credstash secret name
     * @param secret The secret value
     * @param kmsKeyId The KMS KeyId used to generate a new data key
     * @param context Encryption context for integrity check
     * @param version An option version string to be used when stashing the secret, defaults to '1' (padded)
     *
     * @throws com.amazonaws.services.dynamodbv2.model.ConditionalCheckFailedException If the version already exists.
     */
    public void putSecret(String tableName, String secretName, String secret, String kmsKeyId, Map<String, String> context, String version) {

        String newVersion = version;
        if(newVersion == null)
        {
            newVersion = padVersion(1);
        }

        GenerateDataKeyResult generateDataKeyResult = awskmsClient.generateDataKey(new GenerateDataKeyRequest().withKeyId(kmsKeyId).withEncryptionContext(context).withNumberOfBytes(64));
        ByteBuffer plainTextKey = generateDataKeyResult.getPlaintext();
        ByteBuffer cipherTextBlob = generateDataKeyResult.getCiphertextBlob();

        byte[] keyBytes = new byte[32];
        plainTextKey.get(keyBytes);

        byte[] hmacKeyBytes = new byte[plainTextKey.remaining()];
        plainTextKey.get(hmacKeyBytes);

        byte[] encryptedKeyBytes = new byte[cipherTextBlob.remaining()];
        cipherTextBlob.get(encryptedKeyBytes);

        byte[] contents = cryptoImpl.encrypt(keyBytes, secret.getBytes());
        byte[] hmac = cryptoImpl.digest(hmacKeyBytes, contents);

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("name", new AttributeValue(secretName));
        item.put("version", new AttributeValue(newVersion));
        item.put("key", new AttributeValue(new String(Base64.getEncoder().encode(encryptedKeyBytes))));
        item.put("contents", new AttributeValue(new String(Base64.getEncoder().encode(contents))));
        item.put("hmac", new AttributeValue(new String(Hex.encodeHex(hmac))));

        Map<String, String> expressionAttributes = new HashMap<>();
        expressionAttributes.put("#N", "name");

        amazonDynamoDBClient.putItem(new PutItemRequest(tableName, item)
                .withConditionExpression("attribute_not_exists(#N)")
                .withExpressionAttributeNames(expressionAttributes));
    }

    /**
     * Get the highest version of a secret.
     *
     * @param tableName Credstash DynamoDB table name
     * @param secretName Credstash secret name
     * @return The highest version of the secret or null if no secret with that name exists
     */
    public String getHighestVersion(String tableName, String secretName)
    {
        StoredSecret storedSecret = readDynamoItem(tableName, secretName);
        return storedSecret == null ? null : storedSecret.getVersion();
    }

    private String padVersion(int version)
    {
        return String.format("%019d", version);
    }
}