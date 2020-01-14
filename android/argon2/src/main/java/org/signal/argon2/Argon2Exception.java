package org.signal.argon2;

import java.util.Locale;

public final class Argon2Exception extends Exception {

  Argon2Exception(int nativeErrorValue, String nativeErrorMessage) {
    super(String.format(Locale.US, "Argon failed %d: %s", nativeErrorValue, nativeErrorMessage));
  }
}
