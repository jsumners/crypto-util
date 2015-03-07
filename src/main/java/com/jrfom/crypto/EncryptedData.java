package com.jrfom.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.jrfom.crypto.deserializers.EncryptedDataDeserializer;
import com.jrfom.crypto.serializers.EncryptedDataSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An {@linkplain com.jrfom.crypto.EncryptedData} instance represents a block
 * of encrypted data. The instance includes the encrypted data and the
 * Initialization Vector that was used to perform the encryption.
 */
@JsonDeserialize(using = EncryptedDataDeserializer.class)
@JsonSerialize(using = EncryptedDataSerializer.class)
public class EncryptedData {
  private static final Logger log = LoggerFactory.getLogger(EncryptedData.class);

  @JsonProperty("iv")
  private byte[] iv;
  @JsonProperty("data")
  private byte[] data;

  public EncryptedData() {}

  public EncryptedData(byte[] iv, byte[] data) {
    this.iv = iv;
    this.data = data;
  }

  /**
   * Create a new instance of {@linkplain com.jrfom.crypto.EncryptedData} given
   * a {@link java.util.Base64} encoded string that represents a JSON
   * serialization of an {@linkplain com.jrfom.crypto.EncryptedData} instance.
   * Such an instance can be created by encoding the result of
   * {@link com.jrfom.crypto.EncryptedData#toString}.
   *
   * @param b64string The string to process
   * @return An empty {@link java.util.Optional} if there was an error.
   *         Otherwise an Optional wrapped
   *         {@linkplain com.jrfom.crypto.EncryptedData} instance
   */
  public static Optional<EncryptedData> fromBase64(String b64string) {
    Optional<EncryptedData> result = Optional.empty();
    byte[] data;

    try {
      data = Base64.getDecoder().decode(b64string);
      result = EncryptedData.fromJSON(new String(data));
    } catch (IllegalArgumentException e) {
      log.error("Input Base64 string is not valid: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }

  /**
   * The same as {@link com.jrfom.crypto.EncryptedData#fromBase64} except the
   * input string is the same string as would be returned from
   * {@link com.jrfom.crypto.EncryptedData#toString}.
   *
   * @param json
   * @return
   */
  public static Optional<EncryptedData> fromJSON(String json) {
    Optional<EncryptedData> result = Optional.empty();

    try {
      ObjectMapper mapper = new ObjectMapper();
      EncryptedData encryptedData = mapper.readValue(json, EncryptedData.class);

      result = Optional.of(encryptedData);
    } catch (JsonMappingException e) {
      log.error("Could not map JSON to object: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (JsonParseException e) {
      log.error("Could not parse JSON: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (IOException e) {
      log.error("Could not read data: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }

  public byte[] getIv() {
    return this.iv;
  }

  public void setIv(byte[] iv) {
    this.iv = iv;
  }

  public byte[] getData() {
    return this.data;
  }

  public void setData(byte[] data) {
    this.data = data;
  }

  /**
   * Serializes the {@linkplain com.jrfom.crypto.EncryptedData} instance
   * to JSON and returns the result.
   *
   * @return A JSON string on successful serialization, otherwise "not
   *         serialized".
   */
  @Override
  @JsonIgnore
  public String toString() {
    String result = "not serialized";

    try {
      ObjectMapper mapper = new ObjectMapper();
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      mapper.writeValue(stream, this);

      result = stream.toString();
    } catch (JsonMappingException e) {
      log.error("Could not map JSON to object: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (JsonGenerationException e) {
      log.error("Could not generate JSON string: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (IOException e) {
      log.error("Could not perform IO: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }
}