package org.signal.argon2;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.signal.argon2.Argon2;
import org.signal.argon2.Argon2Exception;
import org.signal.argon2.Type;
import org.signal.argon2.Version;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.signal.argon2.TestUtils.ascii;
import static org.signal.argon2.TestUtils.utf8;
import static org.signal.argon2.Type.Argon2i;
import static org.signal.argon2.Type.Argon2id;

@RunWith(AndroidJUnit4.class)
public final class Argon2BuilderTest {

  @Test
  public void memory_too_low() {
    Argon2.Builder builder = new Argon2.Builder(Version.LATEST)
                                       .type(Argon2id);

    assertThatThrownBy(() -> builder.memoryCost(-1))
    .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void memory_too_high() {
    Argon2.Builder builder = new Argon2.Builder(Version.LATEST)
                                       .type(Argon2id);

    assertThatThrownBy(() -> builder.memoryCost(31))
    .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void using_memory_constants() throws Argon2Exception {
    String hash1 = new Argon2.Builder(Version.V13)
                             .type(Argon2id)
                             .memoryCost(MemoryCost.MiB_32)
                             .parallelism(1)
                             .iterations(1)
                             .build()
                             .hash(utf8("signal"), utf8("somesalt"))
                             .getHashHex();

    String hash2 = new Argon2.Builder(Version.V13)
                             .type(Argon2id)
                             .memoryCost(15)
                             .parallelism(1)
                             .iterations(1)
                             .build()
                             .hash(utf8("signal"), utf8("somesalt"))
                             .getHashHex();

    assertEquals(hash1, hash2);
  }
}
