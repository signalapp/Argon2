package org.signal.argon2;

import java.util.Locale;

public final class Argon2Exception extends Exception {

  Argon2Exception(String message) {
    super(message);
  }

  Argon2Exception(int nativeErrorValue, String nativeErrorMessage) {
    this(String.format(Locale.US, "Argon failed %d: %s", nativeErrorValue, nativeErrorMessage));
  }
}
