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