package org.signal.argon2;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.signal.argon2.TestUtils.utf8;
import static org.signal.argon2.Type.Argon2id;

public final class Argon2BadParameterTest {

 @Test
  public void null_password() {
    Argon2 argon2 = new Argon2.Builder(Version.V13)
                              .type(Argon2id)
                              .memoryCost(MemoryCost.MiB(32))
                              .parallelism(1)
                              .iterations(1)
                              .build();
    //noinspection ConstantConditions
    assertThatThrownBy(()-> argon2.hash(null, utf8("somesalt")))
      .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void null_salt() {
    Argon2 argon2 = new Argon2.Builder(Version.V13)
                              .type(Argon2id)
                              .memoryCost(MemoryCost.MiB(32))
                              .parallelism(1)
                              .iterations(1)
                              .build();
    //noinspection ConstantConditions
    assertThatThrownBy(() -> argon2.hash(utf8("signal"), null))
      .isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void verify_with_null_password() {
    //noinspection ConstantConditions
    assertThatThrownBy(() ->
      Argon2.verify("$argon2id$v=19$m=32768,t=1,p=1$c29tZXNhbHQ$5d38aTyOwp6kx3ALaN/k04OsQ98uO6FRLo5XYsy9gZ4", null, Argon2id)
    ).isExactlyInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void verify_with_null_encoded() {
    //noinspection ConstantConditions
    assertThatThrownBy(() ->
      Argon2.verify(null, utf8("signal"), Argon2id)
    ).isExactlyInstanceOf(IllegalArgumentException.class);
  }
}
