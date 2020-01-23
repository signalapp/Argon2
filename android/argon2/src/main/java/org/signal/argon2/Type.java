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

  public static Type fromEncoded(String encoded) throws UnknownTypeException {
    if (encoded == null) throw new IllegalArgumentException();

    if (encoded.startsWith("$argon2id$")) return Argon2id;
    if (encoded.startsWith("$argon2i$" )) return Argon2i;
    if (encoded.startsWith("$argon2d$" )) return Argon2d;

    throw new UnknownTypeException();
  }
}
