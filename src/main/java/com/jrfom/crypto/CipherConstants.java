package com.jrfom.crypto;

/**
 * <p>Provides constants for {@link javax.crypto.Cipher} algorithms,
 * algorithm modes, and algorithm paddings. For details on each, see:</p>
 *
 * <p>
 *   <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher">Cipher Names</a>
 * </p>
 *
 * <p>It also provides some static methods that return common combinations
 * of algorithms, modes, and paddings.</p>
 *
 * @since 0.2.0
 */
public class CipherConstants {
  // Algorithms
  public static final String ALGO_AES = "AES";
  public static final String ALGO_AESWrap = "AESWrap";
  public static final String ALGO_ARC4 = "ARCFOUR";
  public static final String ALGO_BLOWFISH = "Blowfish";
  public static final String ALGO_DES = "DES";
  public static final String ALGO_DESEDE = "DESede";
  public static final String ALGO_DESEDEWRAP = "DESedeWrap";
  public static final String ALGO_ECIES = "ECIES";
  public static final String ALGO_RC2 = "RC2";
  public static final String ALGO_RC4 = "RC4";
  public static final String ALGO_RC5 = "RC5";
  public static final String ALGO_RSA = "RSA";

  // Modes
  public static final String MODE_NONE = "NONE";
  public static final String MODE_CBC = "CBC";
  public static final String MODE_CCM = "CCM";
  public static final String MODE_CFB = "CFB";
  public static final String MODE_CTR = "CTR";
  public static final String MODE_CTS = "CTS";
  public static final String MODE_ECB = "ECB";
  public static final String MODE_GCM = "GCM";
  public static final String MODE_OFB = "OFB";
  public static final String MODE_PCBC = "PCBC";

  // Paddings
  public static final String PAD_NONE = "NoPadding";
  public static final String PAD_ISO10126 = "ISO10126Padding";
  public static final String PAD_OAE = "OAEPadding";
  public static final String PAD_PKCS1 = "PKCS1Padding";
  public static final String PAD_PKCS5 = "PKCS5Padding";
  public static final String PAD_SSL3 = "SSL3Padding";

  /**
   * Standard AES algorithm using the CBC mode and PKCS5 padding.
   *
   * @return "AES/CBC/PKCS5Padding"
   */
  public static String AesCbcPad5() {
    return String.format(
      "%s/%s/%s",
      CipherConstants.ALGO_AES,
      CipherConstants.MODE_CBC,
      CipherConstants.PAD_PKCS5
      );
  }
}