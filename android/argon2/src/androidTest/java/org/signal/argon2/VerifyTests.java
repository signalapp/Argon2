package org.signal.argon2;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertTrue;
import static org.signal.argon2.TestUtils.utf8;
import static org.signal.argon2.Type.Argon2d;
import static org.signal.argon2.Type.Argon2i;
import static org.signal.argon2.Type.Argon2id;

public final class VerifyTests {

  @Test
  public void verify_argon2d_specifying_type() {
    assertTrue(Argon2.verify("$argon2d$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$AQZ5maf/c48fwRjlcN4vwK7AXDAwtfwe7MTYI8+27T8", utf8("signal"), Argon2d));
  }

  @Test
  public void verify_argon2d_not_specifying_type() throws UnknownTypeException {
    assertTrue(Argon2.verify("$argon2d$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$AQZ5maf/c48fwRjlcN4vwK7AXDAwtfwe7MTYI8+27T8", utf8("signal")));
  }

  @Test
  public void verify_argon2i_specifying_type() {
    assertTrue(Argon2.verify("$argon2i$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$F1TwhdCXduq6IqFH+gob2M5rpSok5w2c1YdaTKm6wvw", utf8("signal"), Argon2i));
  }

  @Test
  public void verify_argon2i_not_specifying_type() throws UnknownTypeException {
    assertTrue(Argon2.verify("$argon2i$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$F1TwhdCXduq6IqFH+gob2M5rpSok5w2c1YdaTKm6wvw", utf8("signal")));
  }

  @Test
  public void verify_argon2id_specifying_type() {
    assertTrue(Argon2.verify("$argon2id$v=19$m=32768,t=1,p=1$c29tZXNhbHQ$5d38aTyOwp6kx3ALaN/k04OsQ98uO6FRLo5XYsy9gZ4", utf8("signal"), Argon2id));
  }

  @Test
  public void verify_argon2id_not_specifying_type() throws UnknownTypeException {
    assertTrue(Argon2.verify("$argon2id$v=19$m=32768,t=1,p=1$c29tZXNhbHQ$5d38aTyOwp6kx3ALaN/k04OsQ98uO6FRLo5XYsy9gZ4", utf8("signal")));
  }

  @Test
  public void unknown() {
    assertThatThrownBy(() -> Argon2.verify("$argon2dx$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$AQZ5maf/c48fwRjlcN4vwK7AXDAwtfwe7MTYI8+27T8", utf8("signal")))
      .isExactlyInstanceOf(UnknownTypeException.class);
  }
}
