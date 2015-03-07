package com.jrfom.crypto;

import java.security.Key;

/**
 * An implementation of {@link com.jrfom.crypto.CryptoTool} that is specific
 * to the AES algorithm. It uses the mode "AES/CBC/PKCS5Padding".
 */
public class AesCryptoTool extends AbstractCryptoTool {

  /**
   * Create an instance using the specified key.
   *
   * @param key A {@link java.security.Key} instance set to the "AES"
   *            algorithm. The key size should be 16.
   */
  public AesCryptoTool(Key key) {
    this("AES", "AES/CBC/PKCS5Padding", 16);
    this.key = key;
  }

  private AesCryptoTool(String algorithm, String algorithmMode, Integer ivSize) {
    super(algorithm, algorithmMode, ivSize);
  }
}