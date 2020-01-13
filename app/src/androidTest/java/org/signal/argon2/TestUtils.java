package org.signal.argon2;

import java.nio.charset.StandardCharsets;

public final class TestUtils {

  public static byte[] ascii(String s) {
    return s.getBytes(StandardCharsets.US_ASCII);
  }

  public static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  public static byte[] hexToBytes(String hex) {
    byte[] data = new byte[hex.length() / 2];
    for (int i = 0; i < data.length; i ++) {
      data[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                       + Character.digit(hex.charAt(i * 2 + 1), 16));
    }
    return data;
  }
}
