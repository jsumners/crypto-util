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

  @Test
  public void testEncryptWithIv() throws Exception {
    AbstractCryptoTool tool =
      new AbstractCryptoTool("AES", "AES/CBC/PKCS5Padding", 16);
    tool.setKey(this.key);
    byte[] iv = Base64.getDecoder().decode("VSadcPgqXYoegXchXrej2Q==");

    Optional<EncryptedData> encryptedDataOptional =
      tool.encrypt("foobar".getBytes(), iv);
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

  @Test
  public void testReEncryptWithIv() throws Exception {
    AbstractCryptoTool tool =
      new AbstractCryptoTool(CipherConstants.ALGO_AES, CipherConstants.AesCbcPad5(), 16);
    tool.setKey(this.key);

    Optional<EncryptedData> encryptedDataOptional1 =
      tool.encrypt("foobar".getBytes());
    assertTrue(encryptedDataOptional1.isPresent());

    byte[] iv = encryptedDataOptional1.get().getIv();
    Optional<EncryptedData> encryptedDataOptional2 =
      tool.encrypt("foobar".getBytes(), iv);
    assertTrue(encryptedDataOptional2.isPresent());

    EncryptedData ed1 = encryptedDataOptional1.get();
    EncryptedData ed2 = encryptedDataOptional2.get();

    String data1 = Base64.getEncoder().encodeToString(ed1.getData());
    String data2 = Base64.getEncoder().encodeToString(ed2.getData());
    String iv1 = Base64.getEncoder().encodeToString(ed1.getIv());
    String iv2 = Base64.getEncoder().encodeToString(ed2.getIv());

    assertEquals(data1, data2);
    assertEquals(iv1, iv2);
  }
}