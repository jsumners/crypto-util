package com.jrfom.crypto;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;

import javax.crypto.KeyGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>Provides methods for getting {@link java.security.Key} instances that
 * are based on secure PRNGs.</p>
 *
 * <p>See the following article for some pertinent information about how
 * keys are generated and their limitations:</p>
 *
 * <p>
 *   <a href="http://javamex.com/tutorials/cryptography/key_size.shtml">http://javamex.com/tutorials/cryptography/key_size.shtml</a>
 * </p>
 *
 * @since 0.2.0
 */
public class KeyTool {
  private static final Logger log = LoggerFactory.getLogger(KeyTool.class);

  private final SecureRandom random;

  public KeyTool() {
    this(new SecureRandom());
  }

  public KeyTool(SecureRandom secureRandom) {
    this.random = secureRandom;
  }

  /**
   * Generate a 128-bit AES key.
   *
   * @return
   */
  public Optional<Key> aes128key() {
    return this.keyForAlgorithmAtBits("AES", 128);
  }

  /**
   * <p>Generate a 256-bit AES key.</p>
   *
   * <p><strong>NOTE:</strong> this has a high likelyhood of failing.</p>
   * @return
   */
  public Optional<Key> aes256key() {
    return this.keyForAlgorithmAtBits("AES", 256);
  }

  /**
   * <p>Generates a key to be used when encrypting and decrypting data. This key
   * should be retained or else you will no longer be able to decrypt your
   * encrypted data.</p>
   *
   * <p>You shoud use {@link javax.crypto.Cipher#getMaxAllowedKeyLength}
   * to determine if your desired key strength is possible with your
   * installation of Java. Most installations are restricted to 128-bit. See
   * the following article for information on removing the restriction:</p>
   *
   * <p>
   *   <a href="http://javamex.com/tutorials/cryptography/key_size.shtml">http://javamex.com/tutorials/cryptography/key_size.shtml</a>
   * </p>
   *
   * @param algorithm A valid {@link javax.crypto.Cipher} algorightm name,
   *                  e.g "AES"
   * @param bits      The strength of the key to generate (e.g. 128 or 256)
   *
   * @return An empty {@link java.util.Optional} on error. Otherwise
   *         an Optional wrapped random {@link java.security.Key}
   */
  public Optional<Key> keyForAlgorithmAtBits(String algorithm, Integer bits) {
    Optional<Key> result = Optional.empty();

    try {
      KeyGenerator generator = KeyGenerator.getInstance("AES");
      generator.init(bits, this.random);
      Key key = generator.generateKey();
      result = Optional.of(key);
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not find algorithm: `{}`", algorithm);
      log.debug(e.toString());
    }

    return result;
  }
}