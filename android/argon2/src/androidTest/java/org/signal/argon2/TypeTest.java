package org.signal.argon2;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.signal.argon2.Type.Argon2d;
import static org.signal.argon2.Type.Argon2i;
import static org.signal.argon2.Type.Argon2id;

public final class TypeTest {

  @Test
  public void can_parse_argon2id() throws UnknownTypeException {
    assertEquals(Argon2id, Type.fromEncoded("$argon2id$v=19$m=32768,t=1,p=1$c29tZXNhbHQ$5d38aTyOwp6kx3ALaN/k04OsQ98uO6FRLo5XYsy9gZ4"));
  }

  @Test
  public void can_parse_argon2i() throws UnknownTypeException {
    assertEquals(Argon2i, Type.fromEncoded("$argon2i$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$F1TwhdCXduq6IqFH+gob2M5rpSok5w2c1YdaTKm6wvw"));
  }

  @Test
  public void can_parse_argon2d() throws UnknownTypeException {
    assertEquals(Argon2d, Type.fromEncoded("$argon2d$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$AQZ5maf/c48fwRjlcN4vwK7AXDAwtfwe7MTYI8+27T8"));
  }

  @Test
  public void cant_parse_unknown() {
    assertThatThrownBy(() -> Type.fromEncoded("$argon2idx$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$AQZ5maf/c48fwRjlcN4vwK7AXDAwtfwe7MTYI8+27T8"))
      .isExactlyInstanceOf(UnknownTypeException.class);
  }

  @Test
  public void cant_parse_null() {
    //noinspection ConstantConditions
    assertThatThrownBy(() -> Type.fromEncoded(null))
      .isExactlyInstanceOf(IllegalArgumentException.class);
  }
}
