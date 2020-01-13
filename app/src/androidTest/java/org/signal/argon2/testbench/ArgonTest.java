package org.signal.argon2.testbench;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.signal.argon2.Argon2;
import org.signal.argon2.Argon2Exception;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.signal.argon2.Argon2.Type.Argon2i;
import static org.signal.argon2.Argon2.Type.Argon2id;

/**
 * Cases ported from test.c
 */
@RunWith(AndroidJUnit4.class)
public final class ArgonTest {

  @Test
  public void argon_version_10_2i() throws Argon2Exception {
    Argon2.Version version = Argon2.Version.ARGON2_VERSION_10;
    Argon2.Type type = Argon2i;

    hashtest(version, 2, 16, 1, "password", "somesalt",
      "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
      "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" +
        "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", type);
//#ifdef TEST_LARGE_RAM
//    hashtest(version, 2, 20, 1, "password", "somesalt",
//            "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
//            "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk", Argon2i);
//#endif
    hashtest(version, 2, 18, 1, "password", "somesalt",
      "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
      "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ" +
        "$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc", type);
    hashtest(version, 2, 8, 1, "password", "somesalt",
      "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
      "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ" +
        "$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY", type);
    hashtest(version, 2, 8, 2, "password", "somesalt",
      "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
      "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ" +
        "$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs", type);
    hashtest(version, 1, 16, 1, "password", "somesalt",
      "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
      "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ" +
        "$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI", type);
    hashtest(version, 4, 16, 1, "password", "somesalt",
      "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
      "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ" +
        "$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs", type);
    hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
      "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
      "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" +
        "$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM", type);
    hashtest(version, 2, 16, 1, "password", "diffsalt",
      "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
      "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ" +
        "$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc", type);
  }

  @Test
  public void argon_version_latest_2i() throws Argon2Exception {

    Argon2.Version version = Argon2.Version.ARGON2_VERSION_NUMBER;
    Argon2.Type type = Argon2i;

    hashtest(version, 2, 16, 1, "password", "somesalt",
      "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
      "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" +
        "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", type);
//#ifdef TEST_LARGE_RAM
//    hashtest(version, 2, 20, 1, "password", "somesalt",
//             "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
//             "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ"
//             "$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E", Argon2i);
//#endif
    hashtest(version, 2, 18, 1, "password", "somesalt",
      "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
      "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ" +
        "$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s", type);
    hashtest(version, 2, 8, 1, "password", "somesalt",
      "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
      "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ" +
        "$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8", type);
    hashtest(version, 2, 8, 2, "password", "somesalt",
      "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
      "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ" +
        "$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E", type);
    hashtest(version, 1, 16, 1, "password", "somesalt",
      "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
      "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ" +
        "$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8", type);
    hashtest(version, 4, 16, 1, "password", "somesalt",
      "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
      "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ" +
        "$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls", type);
    hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
      "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
      "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" +
        "$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4", type);
    hashtest(version, 2, 16, 1, "password", "diffsalt",
      "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
      "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ" +
        "$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE", type);
  }

  @Test
  public void argon_version_latest_2id() throws Argon2Exception {
    Argon2.Version version = Argon2.Version.ARGON2_VERSION_NUMBER;
    Argon2.Type type = Argon2id;

    hashtest(version, 2, 16, 1, "password", "somesalt",
      "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
      "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" +
        "$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc", type);
    hashtest(version, 2, 18, 1, "password", "somesalt",
      "78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c",
      "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ" +
        "$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow", type);
    hashtest(version, 2, 8, 1, "password", "somesalt",
      "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
      "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ" +
        "$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", type);
    hashtest(version, 2, 8, 2, "password", "somesalt",
      "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
      "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ" +
        "$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc", type);
    hashtest(version, 1, 16, 1, "password", "somesalt",
      "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
      "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ" +
        "$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg", type);
    hashtest(version, 4, 16, 1, "password", "somesalt",
      "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c",
      "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ" +
        "$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw", type);
    hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
      "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde",
      "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" +
        "$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94", type);
    hashtest(version, 2, 16, 1, "password", "diffsalt",
      "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c",
      "$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ" +
        "$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw", type);
  }

  /**
   * Test harness will assert:
   * argon2_hash() returns ARGON2_OK
   * HEX output matches expected
   * encoded output matches expected
   * Argon2.verify() correctly verifies value
   */
  private static void hashtest(Argon2.Version version, int t, int m, int p, String password, String salt, String hexref, String mcRef, Argon2.Type type) throws Argon2Exception {
    Argon2 argon2 = new Argon2.Builder()
                      .version(version)
                      .type(type)
                      .iterations(t)
                      .memory(m)
                      .parallelism(p)
                      .hashLength(32)
                      .build();

    Argon2.Result result = argon2.hash(ascii(password), ascii(salt));

    assertEquals(hexref, result.getHashHex());
    assertArrayEquals(hexToBytes(hexref), result.getHash());
    if (version != Argon2.Version.ARGON2_VERSION_10) {
      assertEquals(mcRef, result.getEncoded());
    }

    assertTrue(Argon2.verify(result.getEncoded(), ascii(password), type));
    assertTrue(Argon2.verify(mcRef, ascii(password), type));
  }

  @Test
  public void argon_version_10_2i_verify_errors() {
    // Handle an invalid encoding correctly (it is missing a $)
    assertFalse(Argon2.verify("$argon2i$m=65536,t=2,p=1c29tZXNhbHQ" +
                                "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
      ascii("password"), Argon2i));

    // Handle an invalid encoding correctly (it is missing a $)
    assertFalse(Argon2.verify("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" +
                                "9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
      ascii("password"), Argon2i));

    // Handle an invalid encoding correctly (salt is too short)
    assertFalse(Argon2.verify("$argon2i$m=65536,t=2,p=1$" +
                                "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
      ascii("password"), Argon2i));

    // Handle an mismatching hash (the encoded password is "passwore")
    assertFalse(Argon2.verify("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" +
                                "$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo",
      ascii("password"), Argon2i));
  }

  @Test
  public void argon_version_13_2i_verify_errors() {
    /* Handle an invalid encoding correctly (it is missing a $) */
    assertFalse(Argon2.verify("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ"+
                        "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
      ascii("password"), Argon2i));

    /* Handle an invalid encoding correctly (it is missing a $) */
    assertFalse(Argon2.verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"+
                        "wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
      ascii("password"), Argon2i));

    /* Handle an invalid encoding correctly (salt is too short) */
    assertFalse(Argon2.verify("$argon2i$v=19$m=65536,t=2,p=1$"+
                        "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
      ascii("password"), Argon2i));

    /* Handle an mismatching hash (the encoded password is "passwore") */
    assertFalse(Argon2.verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ"+
                        "$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM",
      ascii("password"), Argon2i));
  }

  @Test
  public void memory_too_little() {
    Argon2 argon2 = new Argon2.Builder()
                              .type(Argon2id)
                              .memory(2)
                              .build();

    assertThatThrownBy(() -> argon2.hash(ascii("password"), ascii("diffsalt")))
    .isExactlyInstanceOf(Argon2Exception.class)
    .hasMessageContaining("Memory cost is too small");
  }

  @Test
  public void salt_too_short() {
    Argon2 argon2 = new Argon2.Builder()
                              .type(Argon2id)
                              .build();

    assertThatThrownBy(() -> argon2.hash(ascii("password"), ascii("s")))
    .isExactlyInstanceOf(Argon2Exception.class)
    .hasMessageContaining("Salt is too short");
  }

  @Test
  public void memory_too_low_in_builder() {
    Argon2.Builder builder = new Argon2.Builder()
                                       .type(Argon2id);

    assertThatThrownBy(() -> builder.memory(-1))
    .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void memory_too_high_in_builder() {
    Argon2.Builder builder = new Argon2.Builder()
                                       .type(Argon2id);

    assertThatThrownBy(() -> builder.memory(31))
    .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  private static byte[] ascii(String password) {
    return password.getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] hexToBytes(String hex) {
    byte[] data = new byte[hex.length() / 2];
    for (int i = 0; i < data.length; i ++) {
      data[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                       + Character.digit(hex.charAt(i * 2 + 1), 16));
    }
    return data;
  }
}
