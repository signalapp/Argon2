package org.signal.argon2;

/**
 * Version of the Argon2 algorithm.
 */
public enum Version {
  V10(0x10),
  V13(0x13),
  LATEST(0x13);

  final int nativeValue;

  Version(int nativeValue) {
    this.nativeValue = nativeValue;
  }
}
