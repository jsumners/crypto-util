package com.jrfom.crypto;

import java.util.Base64;
import java.util.Optional;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class EncryptedDataTest {
  private Base64.Encoder encoder = Base64.getEncoder();

  @Test
  public void testFromJSON() throws Exception {
    Optional<EncryptedData> encryptedDataOptional = EncryptedData.fromJSON(
      "{\"iv\": \"VSadcPgqXYoegXchXrej2Q==\"," +
      "\"data\": \"66qbexIcG0VlGHw5E2JHcA==\"}"
    );
    assertTrue(encryptedDataOptional.isPresent());

    EncryptedData encryptedData = encryptedDataOptional.get();
    assertEquals(
      "VSadcPgqXYoegXchXrej2Q==",
      this.encoder.encodeToString(encryptedData.getIv())
    );
    assertEquals(
      "66qbexIcG0VlGHw5E2JHcA==",
      this.encoder.encodeToString(encryptedData.getData())
    );
  }

  @Test
  public void testToString() throws Exception {
    String sourceJSON = "{\"iv\":\"VSadcPgqXYoegXchXrej2Q==\"," +
      "\"data\":\"66qbexIcG0VlGHw5E2JHcA==\"}";
    Optional<EncryptedData> encryptedDataOptional =
      EncryptedData.fromJSON(sourceJSON);
    assertTrue(encryptedDataOptional.isPresent());

    String JSON = encryptedDataOptional.get().toString();
    assertEquals(sourceJSON, JSON);
  }
}