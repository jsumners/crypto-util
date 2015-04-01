package com.jrfom.crypto;

import java.util.Optional;

/**
 * Implementations of {@linkplain com.jrfom.crypto.CryptoTool} provide means
 * to perform encryption and decryption using specific agorithms.
 */
public interface CryptoTool {
  /**
   * Decrypt a specified {@link com.jrfom.crypto.EncryptedData} using the
   * algorithm of the {@link com.jrfom.crypto.CryptoTool} implemntation.
   *
   * @param data Data that has been encrypted using the implementations algorithm
   * @return An empty {@link java.util.Optional} if there was an error.
   *         Otherwise an Optional wrapped byte array of the encrypted data that
   *         was stored in {@link com.jrfom.crypto.EncryptedData#getData}.
   */
  Optional<byte[]> decrypt(EncryptedData data);

  /**
   * Encrypt the specified {@code data} using the algorithm of the
   * {@link com.jrfom.crypto.CryptoTool} implementation.
   *
   * @param data The data to be encrypted
   * @return An empty {@link java.util.Optional} if there was an error.
   *         Otherwise an Optional wrapped instance of
   *         {@link com.jrfom.crypto.EncryptedData}.
   */
  Optional<EncryptedData> encrypt(byte[] data);

  /**
   * Encrypt the specified {@code data} using the algorithm of the
   * {@link CryptoTool} implementation and the given initialization vector,
   * {@code iv}.
   *
   * @param data The data to be encrypted
   * @param iv The initialization vector to be use. It must be of appropriate
   *           size for the algorithm of the {@link CryptoTool} implementation
   * @return An empty {@link java.util.Optional} if there was an error.
   *         Otherwise an Optional wrapped instance of {@link EncryptedData}
   */
  Optional<EncryptedData> encrypt(byte[] data, byte[] iv);
}