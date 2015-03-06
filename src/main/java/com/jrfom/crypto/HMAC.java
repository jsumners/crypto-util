package com.jrfom.crypto;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Mac;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides utility methods for computing {@link javax.crypto.Mac} hashes.
 */
public class HMAC {
  private static final Logger log = LoggerFactory.getLogger(HMAC.class);

  public static final String ALGO_MD5 = "HmacMD5";
  public static final String ALGO_SHA1 = "HmacSHA1";
  public static final String ALGO_SHA256 = "HmacSHA256";

  /**
   * Get a MD5 based HMAC hash for the specified data and secret key.
   *
   * @see HMAC#forDataWithKeyAndAlgorithm
   */
  public static Optional<String> md5ForDataWithKey(byte[] data, Key key) {
    return HMAC.forDataWithKeyAndAlgorithm(data, key, HMAC.ALGO_MD5);
  }

  /**
   * Get a SHA1 based HMAC hash for the specified data and secret key.
   *
   * @see HMAC#forDataWithKeyAndAlgorithm
   */
  public static Optional<String> sha1ForDataWithKey(byte[] data, Key key) {
    return HMAC.forDataWithKeyAndAlgorithm(data, key, HMAC.ALGO_SHA1);
  }

  /**
   * Get a SHA256 based HMAC hash for the specified data and secret key.
   *
   * @see HMAC#forDataWithKeyAndAlgorithm
   */
  public static Optional<String> sha256ForDataWithKey(byte[] data, Key key) {
    return HMAC.forDataWithKeyAndAlgorithm(data, key, HMAC.ALGO_SHA256);
  }

  /**
   * <p>Computes the
   * <a href="http://en.wikipedia.org/wiki/Hash-based_message_authentication_code">HMAC</a>
   * hash for a given data set using the provided secret
   * {@link java.security.Key}.</p>
   *
   * @param data Bytes of data to compute the HMAC for
   * @param key A valid {@link javax.crypto.spec.SecretKeySpec} instance
   * @param algorithm <p>A valid HMAC computation algorithm. Some possible
   *                  values are:</p>
   *                  <ul>
   *                    <li>{@link HMAC#ALGO_MD5}</li>
   *                    <li>{@link HMAC#ALGO_SHA1}</li>
   *                    <li>{@link HMAC#ALGO_SHA256}</li>
   *                  </ul>
   * @return <p>An empty {@link java.util.Optional} if there was an error.
   *         Otherwise, the Optional contains a {@link java.util.Base64}
   *         encoded string of the hash bytes.</p>
   */
  public static Optional<String> forDataWithKeyAndAlgorithm(byte[] data, Key key, String algorithm)
  {
    Optional<String> result = Optional.empty();

    try {
      Mac mac = Mac.getInstance(algorithm);
      mac.init(key);

      byte[] encryptedBytes = mac.doFinal(data);
      String b64hash = Base64.getEncoder().encodeToString(encryptedBytes);
      result = Optional.of(b64hash);
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not find HmacSHA256 algorithm: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (InvalidKeyException e) {
      log.error("Invalid key: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }
}