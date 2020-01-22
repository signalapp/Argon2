package org.signal.argon2;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.signal.argon2.TestUtils.utf8;
import static org.signal.argon2.Type.Argon2id;

@RunWith(AndroidJUnit4.class)
public final class Argon2BuilderTest {

  @Test
  public void memory_too_low() {
    Argon2.Builder builder = new Argon2.Builder(Version.LATEST)
                                       .type(Argon2id);

    assertThatThrownBy(() -> builder.memoryCostKiB(-1))
      .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void memory_too_high() {
    Argon2.Builder builder = new Argon2.Builder(Version.LATEST)
                                       .type(Argon2id);

    assertThatThrownBy(() -> builder.memoryCostOrder(31))
      .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void using_MemoryCost_object() throws Argon2Exception {
    String hash1 = new Argon2.Builder(Version.V13)
                             .type(Argon2id)
                             .memoryCost(MemoryCost.MiB(32))
                             .parallelism(1)
                             .iterations(1)
                             .build()
                             .hash(utf8("signal"), utf8("somesalt"))
                             .getEncoded();

    assertEquals(hash1, "$argon2id$v=19$m=32768,t=1,p=1$c29tZXNhbHQ$5d38aTyOwp6kx3ALaN/k04OsQ98uO6FRLo5XYsy9gZ4");
  }
}
