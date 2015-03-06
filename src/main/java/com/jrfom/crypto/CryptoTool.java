package com.jrfom.crypto;

import java.util.Optional;

public interface CryptoTool {
  Optional<byte[]> decrypt(EncryptedData data);
  Optional<EncryptedData> encrypt(byte[] data);
}