package org.signal.argon2;

final class Argon2Native {

  static final int OK = 0;

  static {
    System.loadLibrary("argon2");
  }

  static native int argon2_hash(int t_cost,
                                int m_cost,
                                int parallelism,
                                byte[] pwd,
                                byte[] salt,
                                byte[] hash,
                                StringBuffer encoded,
                                int argon2_type,
                                int version);

  static native int argon2_verify(String encoded, byte[] pwd, int argon2_type);

  static native String argon2_error_string(int argonResult);
}
