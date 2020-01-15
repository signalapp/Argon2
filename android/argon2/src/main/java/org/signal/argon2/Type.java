package org.signal.argon2;

/**
 * Argon2 primitive type.
 */
public enum Type {
  Argon2d(0),
  Argon2i(1),
  Argon2id(2);

  final int nativeValue;

  Type(int nativeValue) {
    this.nativeValue = nativeValue;
  }
}
