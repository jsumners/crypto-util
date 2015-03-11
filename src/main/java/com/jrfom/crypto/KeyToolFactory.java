package com.jrfom.crypto;

import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides utility methods for getting insances of
 * {@link com.jrfom.crypto.KeyTool}.
 *
 * @since 0.2.0
 */
public class KeyToolFactory {
  private static final Logger log = LoggerFactory.getLogger(KeyToolFactory.class);

  /**
   * Get a {@link com.jrfom.crypto.KeyTool} instance that uses the default
   * {@link sun.security.provider.SecureRandom} PRNG.
   *
   * @return
   */
  public static KeyTool getInstance() {
    return new KeyTool(new SecureRandom());
  }

  /**
   * Get a {@link com.jrfom.crypto.KeyTool} instance that used the passed
   * in {@link java.security.SecureRandom} PRNG implementation (i.e. one
   * returned by a {@code getInstance} method on the
   * {@link java.security.SecureRandom} class).
   *
   * @param random A PRNG to be used for key creation
   * @return
   */
  public static KeyTool getInstanceWithRandom(SecureRandom random) {
    return new KeyTool(random);
  }
}