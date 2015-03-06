package com.jrfom.crypto.serializers;

import java.io.IOException;
import java.util.Base64;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.jrfom.crypto.EncryptedData;

public class EncryptedDataSerializer extends JsonSerializer<EncryptedData> {
  @Override
  public void serialize(EncryptedData encryptedData, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
    throws IOException, JsonProcessingException
  {
    Base64.Encoder encoder = Base64.getEncoder();
    ObjectCodec codec = jsonGenerator.getCodec();

    jsonGenerator.writeStartObject();

    jsonGenerator.writeObjectField(
      "iv",
      encoder.encodeToString(encryptedData.getIv())
    );
    jsonGenerator.writeObjectField(
      "data",
      encoder.encodeToString(encryptedData.getData())
    );

    jsonGenerator.writeEndObject();
  }
}