package com.jrfom.crypto;

import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>A base implementation of {@link com.jrfom.crypto.CryptoTool}. This
 * implemenation does not implement a specific encryption algorithm. As such,
 * it can be extended to create implementations that are specific to individual
 * algorithms. Alternatively, it can be used directly to use an algorithm
 * for which there is not a specific implementation.</p>
 *
 * <p>See {@link com.jrfom.crypto.CipherConstants} for easy access to
 * algorithm, algorithm mode, and padding constants.</p>
 */
public class AbstractCryptoTool implements CryptoTool {
  private final Logger log = LoggerFactory.getLogger(this.getClass().getName());

  protected String algorithm;
  protected String algorithmMode;
  protected Integer ivSize;
  protected Key key;

  /**
   * Create a new instance for the specified algorithm. Before the instance
   * can be used you <strong>must</strong> add a key using
   * {@link com.jrfom.crypto.AbstractCryptoTool#setKey}.
   *
   * @param algorithm The algorithm the instance use for encryption/decryption
   * @param algorithmMode The processing mode fo the specified algorithm
   * @param ivSize The expected initialization vector length for the algorithm
   */
  public AbstractCryptoTool(String algorithm, String algorithmMode, Integer ivSize) {
    this.algorithm = algorithm;
    this.algorithmMode = algorithmMode;
    this.ivSize = ivSize;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Optional<byte[]> decrypt(EncryptedData data) {
    Optional<byte[]> result = Optional.empty();
    Optional<Cipher> cipherOptional = Optional.empty();

    try {
      cipherOptional = this.getDecryptCipher(data.getIv());
    } catch (Exception e) {
      log.error("Could not get Cipher instance: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    if (cipherOptional.isPresent()) {
      try {
        Cipher cipher = cipherOptional.get();
        byte[] decryptedBytes = cipher.doFinal(data.getData());
        result = Optional.of(decryptedBytes);
      } catch (IllegalBlockSizeException e) {
        log.error("Bad encryption block size: `{}`", e.getMessage());
        log.debug(e.toString());
      } catch (BadPaddingException e) {
        log.error("Bad encryption padding size: `{}`", e.getMessage());
        log.debug(e.toString());
      }
    }

    return result;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Optional<EncryptedData> encrypt(byte[] data) {
    Optional<EncryptedData> result = Optional.empty();
    Optional<Cipher> cipherOptional = Optional.empty();

    try {
      cipherOptional = this.getEncryptCipher();
    } catch (Exception e) {
      log.error("Could not get Cipher instance: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    if (cipherOptional.isPresent()) {
      try {
        Cipher cipher = cipherOptional.get();
        byte[] encryptedBytes = cipher.doFinal(data);

        EncryptedData encryptedData = new EncryptedData(
          cipher.getIV(),
          encryptedBytes
        );

        result = Optional.of(encryptedData);
      } catch (IllegalBlockSizeException e) {
        log.error("Bad encryption block size: `{}`", e.getMessage());
        log.debug(e.toString());
      } catch (BadPaddingException e) {
        log.error("Bad encryption padding size: `{}`", e.getMessage());
        log.debug(e.toString());
      }
    }

    return result;
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public void setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  public String getAlgorithmMode() {
    return this.algorithmMode;
  }

  public void setAlgorithmMode(String algorithmMode) {
    this.algorithmMode = algorithmMode;
  }

  public Key getKey() {
    return this.key;
  }

  /**
   * Define the {@link java.security.Key} that will be used for encryption and
   * decryption.
   *
   * @param key
   */
  public void setKey(Key key) {
    this.key = key;
  }

  protected Optional<Cipher> getDecryptCipher(byte[] iv) throws Exception {
    return this.getCipher(Cipher.DECRYPT_MODE, iv);
  }

  protected Optional<Cipher> getEncryptCipher() throws Exception {
    byte[] randomBytes = new byte[this.ivSize];
    SecureRandom random = new SecureRandom();
    random.nextBytes(randomBytes);

    return this.getCipher(Cipher.ENCRYPT_MODE, randomBytes);
  }

  protected Optional<Cipher> getCipher(int mode, byte[] iv) throws Exception {
    Optional<Cipher> result = Optional.empty();

    if (this.key == null) {
      throw new Exception("Key is empty. Must set a key prior to performing operations");
    }

    try {
      Cipher cipher = Cipher.getInstance(this.algorithmMode);

      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      AlgorithmParameters parameters =
        AlgorithmParameters.getInstance(this.algorithm);
      parameters.init(ivParameterSpec);

      cipher.init(mode, this.key, parameters);
      result = Optional.of(cipher);
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not find cipher mode: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (NoSuchPaddingException e) {
      log.error("Could not find padding type: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (InvalidParameterSpecException e) {
      log.error("Algorithm parameter spec invalid: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (InvalidAlgorithmParameterException e) {
      log.error("Algorithm parameters invalid: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (InvalidKeyException e) {
      log.error("Encryption key is invalid: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }
}