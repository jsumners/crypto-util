package com.jrfom.crypto;

import java.security.Key;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AbstractCryptoToolTest {

  private final Key key;

  public AbstractCryptoToolTest() {
    String b64key = "uCntWeIpo4kgDAaGDUQo2w==";
    this.key = new SecretKeySpec(Base64.getDecoder().decode(b64key), "AES");
  }

  @Test
  public void testDecrypt() throws Exception {
    AbstractCryptoTool tool =
      new AbstractCryptoTool("AES", "AES/CBC/PKCS5Padding", 16);
    tool.setKey(this.key);

    Optional<EncryptedData> encryptedDataOptional = EncryptedData.fromJSON(
      "{\"iv\": \"VSadcPgqXYoegXchXrej2Q==\"," +
      "\"data\": \"66qbexIcG0VlGHw5E2JHcA==\"}"
    );

    assertTrue(encryptedDataOptional.isPresent());

    EncryptedData encryptedData = encryptedDataOptional.get();
    Optional<byte[]> dataOptional = tool.decrypt(encryptedData);

    assertTrue(dataOptional.isPresent());
    dataOptional.ifPresent( (data) ->
      assertEquals("foobar", new String(data))
    );
  }

  @Test
  public void testEncrypt() throws Exception {
    AbstractCryptoTool tool =
      new AbstractCryptoTool("AES", "AES/CBC/PKCS5Padding", 16);
    tool.setKey(this.key);

    Optional<EncryptedData> encryptedDataOptional =
      tool.encrypt("foobar".getBytes());
    assertTrue(encryptedDataOptional.isPresent());

    encryptedDataOptional =
      EncryptedData.fromJSON(encryptedDataOptional.get().toString());
    assertTrue(encryptedDataOptional.isPresent());

    EncryptedData encryptedData = encryptedDataOptional.get();
    Optional<byte[]> decryptedOptional = tool.decrypt(encryptedData);

    assertTrue(decryptedOptional.isPresent());
    decryptedOptional.ifPresent( (data) ->
      assertEquals("foobar", new String(data))
    );
  }
}