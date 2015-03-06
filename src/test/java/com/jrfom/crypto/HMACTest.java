package com.jrfom.crypto;

import java.security.Key;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HMACTest {
  private final String text = "The quick brown fox jumps over the lazy dog";

  @Test
  public void testMd5ForDataWithKey() throws Exception {
    Key key = new SecretKeySpec("key".getBytes(), HMAC.ALGO_MD5);
    Optional<String> hmacOptional = HMAC.md5ForDataWithKey(
      this.text.getBytes("ASCII"),
      key
    );

    assertTrue(hmacOptional.isPresent());

    hmacOptional.ifPresent(
      (hmac) -> {
        String hash = this.hashString(Base64.getDecoder().decode(hmac));
        assertEquals("80070713463e7749b90c2dc24911e275", hash);
      }
    );
  }

  @Test
  public void testSha1ForDataWithKey() throws Exception {
    Key key = new SecretKeySpec("key".getBytes(), HMAC.ALGO_SHA1);
    Optional<String> hmacOptional = HMAC.sha1ForDataWithKey(
      this.text.getBytes("ASCII"),
      key
    );

    assertTrue(hmacOptional.isPresent());

    hmacOptional.ifPresent(
      (hmac) -> {
        String hash = this.hashString(Base64.getDecoder().decode(hmac));
        assertEquals("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", hash);
      }
    );
  }

  @Test
  public void testSha256ForDataWithKey() throws Exception {
    Key key = new SecretKeySpec("key".getBytes(), HMAC.ALGO_SHA256);
    Optional<String> hmacOptional = HMAC.sha256ForDataWithKey(
      this.text.getBytes("ASCII"),
      key
    );

    assertTrue(hmacOptional.isPresent());

    hmacOptional.ifPresent(
      (hmac) -> {
        String hash = this.hashString(Base64.getDecoder().decode(hmac));
        assertEquals("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", hash);
      }
    );
  }

  private String hashString(byte[] hashBytes) {
    StringBuilder sb = new StringBuilder();

    for (int i = 0, j = hashBytes.length; i < j; i += 1) {
      String hex = String.format("%02x", hashBytes[i]);
      sb.append(hex);
    }

    return sb.toString();
  }
}