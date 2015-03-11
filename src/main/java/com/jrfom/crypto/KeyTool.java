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
 * <p>This class also provides constants for PRNG types:</p>
 *
 * <ul>
 *   <li>{@link com.jrfom.crypto.KeyTool#PRNG_NATIVE}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#PRNG_NATIVE_BLOCKING}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#PRNG_NATIVE_NONBLOCKING}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#PRNG_PKCS11}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#PRNG_SHA1}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#PRNG_WINDOWS}</li>
 * </ul>
 *
 * <p>It also provides constant for key algorithms:</p>
 *
 * <ul>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_AES}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_ARC4}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_BLOWFISH}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_DES}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_DESEDE}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_HMACMD5}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_HMACSHA1}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_HMACSHA224}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_HMACSHA256}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_HMACSHA384}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_HMACSHA512}</li>
 *   <li>{@link com.jrfom.crypto.KeyTool#ALGO_RC2}</li>
 * </ul>
 *
 * @since 0.2.0
 */
public class KeyTool {
  private static final Logger log = LoggerFactory.getLogger(KeyTool.class);

  // SecureRandom algorithms
  public static final String PRNG_NATIVE = "NativePRNG";
  public static final String PRNG_NATIVE_BLOCKING = "NativePRNGBlocking";
  public static final String PRNG_NATIVE_NONBLOCKING = "NativePRNGNonBlocking";
  public static final String PRNG_PKCS11 = "PKCS11";
  public static final String PRNG_SHA1 = "SHA1PRNG";
  public static final String PRNG_WINDOWS = "Windows-PRNG";

  // Key algorithms
  public static final String ALGO_AES = "AES";
  public static final String ALGO_ARC4 = "ARCFOUR";
  public static final String ALGO_BLOWFISH = "Blowfish";
  public static final String ALGO_DES = "DES";
  public static final String ALGO_DESEDE = "DESede";
  public static final String ALGO_HMACMD5 = "HmacMD5";
  public static final String ALGO_HMACSHA1 = "HmacSHA1";
  public static final String ALGO_HMACSHA224 = "HmacSHA224";
  public static final String ALGO_HMACSHA256 = "HmacSHA256";
  public static final String ALGO_HMACSHA384 = "HmacSHA384";
  public static final String ALGO_HMACSHA512 = "HmacSHA512";
  public static final String ALGO_RC2 = "RC2";

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
    return this.keyForAlgorithmAtBits(KeyTool.ALGO_AES, 128);
  }

  /**
   * <p>Generate a 256-bit AES key.</p>
   *
   * <p><strong>NOTE:</strong> this has a high likelyhood of failing.</p>
   * @return
   */
  public Optional<Key> aes256key() {
    return this.keyForAlgorithmAtBits(KeyTool.ALGO_AES, 256);
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
      KeyGenerator generator = KeyGenerator.getInstance(algorithm);
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