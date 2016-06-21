package com.jessecoyle;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.PutItemResult;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;

import java.nio.ByteBuffer;
import java.util.HashMap;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JCredStashTest {

    private AmazonDynamoDBClient dynamoDBClient;
    private AWSKMSClient awskmsClient;

    @Before
    public void setUp()
    {
        dynamoDBClient = mock(AmazonDynamoDBClient.class);

        GenerateDataKeyResult generateDatakeyResult = new GenerateDataKeyResult();
        generateDatakeyResult.setCiphertextBlob(mock(ByteBuffer.class));
        generateDatakeyResult.setPlaintext(mock(ByteBuffer.class));

        awskmsClient = mock(AWSKMSClient.class);
        when(awskmsClient.generateDataKey(Mockito.any(GenerateDataKeyRequest.class))).thenReturn(generateDatakeyResult);
    }

    @Test
    public void testPutSecretDefaultVersion()
    {
        final PutItemRequest[] putItemRequest = new PutItemRequest[1];
        when(dynamoDBClient.putItem(Mockito.any(PutItemRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            putItemRequest[0] = (PutItemRequest) args[0];
            return new PutItemResult();
        });

        JCredStash credStash = new JCredStash(dynamoDBClient, awskmsClient);
        credStash.putSecret("table", "mysecret", "foo", "alias/foo", new HashMap<>(), null);

        verify(dynamoDBClient, VerificationModeFactory.times(1)).putItem(Mockito.any(PutItemRequest.class));
        Assert.assertEquals(putItemRequest[0].getItem().get("version").getS(), padVersion(1));
    }

    @Test
    public void testPutSecretNewVersion()
    {
        String version = "foover";
        final PutItemRequest[] putItemRequest = new PutItemRequest[1];
        when(dynamoDBClient.putItem(Mockito.any(PutItemRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            putItemRequest[0] = (PutItemRequest) args[0];
            return new PutItemResult();
        });

        JCredStash credStash = new JCredStash(dynamoDBClient, awskmsClient);
        credStash.putSecret("table", "mysecret", "foo", "alias/foo", new HashMap<>(), version);

        verify(dynamoDBClient, VerificationModeFactory.times(1)).putItem(Mockito.any(PutItemRequest.class));
        Assert.assertEquals(putItemRequest[0].getItem().get("version").getS(), version);
    }

    @Test
    public void testPutSecretAutoIncrementVersion()
    {
        final PutItemRequest[] putItemRequest = new PutItemRequest[1];
        when(dynamoDBClient.putItem(Mockito.any(PutItemRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            putItemRequest[0] = (PutItemRequest) args[0];
            return new PutItemResult();
        });

        JCredStash credStash = Mockito.spy(new JCredStash(dynamoDBClient, awskmsClient));
        Mockito.doReturn(padVersion(1)).when(credStash).getHighestVersion("table", "mysecret");
        credStash.putSecret("table", "mysecret", "foo", "alias/foo", new HashMap<>());

        verify(dynamoDBClient, VerificationModeFactory.times(1)).putItem(Mockito.any(PutItemRequest.class));
        Assert.assertEquals(putItemRequest[0].getItem().get("version").getS(), padVersion(2));
    }

    private String padVersion(int v)
    {
        return String.format("%019d", v);
    }
}
