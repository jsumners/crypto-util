package com.jrfom.crypto.deserializers;

import java.io.IOException;
import java.util.Base64;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.jrfom.crypto.EncryptedData;

public class EncryptedDataDeserializer extends JsonDeserializer<EncryptedData> {
  @Override
  public EncryptedData deserialize(JsonParser jp, DeserializationContext ctxt)
    throws IOException, JsonProcessingException
  {
    EncryptedData result = new EncryptedData();
    Base64.Decoder decoder = Base64.getDecoder();
    ObjectCodec codec = jp.getCodec();
    JsonNode node = codec.readTree(jp);

    result.setIv(
      decoder.decode(node.get("iv").asText())
    );

    result.setData(
      decoder.decode(node.get("data").asText())
    );

    return result;
  }
}