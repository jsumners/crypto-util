package com.jrfom.crypto;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Optional;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class KeyToolFactoryTest {

  @Test
  public void testGetInstance() throws Exception {
    KeyTool keyTool = KeyToolFactory.getInstance();
    assertNotNull(keyTool);

    Optional<Key> keyOptional = keyTool.aes128key();
    assertTrue(keyOptional.isPresent());
  }

  @Test
  public void testGetInstanceWithRandom() throws Exception {
    SecureRandom random = SecureRandom.getInstance(KeyTool.PRNG_NATIVE);
    assertNotNull(random);

    KeyTool keyTool = KeyToolFactory.getInstanceWithRandom(random);
    assertNotNull(keyTool);

    Optional<Key> keyOptional = keyTool.aes128key();
    assertTrue(keyOptional.isPresent());
  }
}