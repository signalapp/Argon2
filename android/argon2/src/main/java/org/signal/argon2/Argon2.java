package org.signal.argon2;

import java.util.Locale;

public final class Argon2 {

  private final int     t;
  private final int     m;
  private final int     parallelism;
  private final int     hashLength;
  private final Type    type;
  private final Version version;

  private Argon2(Builder builder) {
    this.t           = builder.t;
    this.m           = builder.m;
    this.parallelism = builder.parallelism;
    this.hashLength  = builder.hashLength;
    this.type        = builder.type;
    this.version     = builder.version;
  }

  public static boolean verify(String encoded, byte[] password, Type type) {
    return Argon2Native.verify(encoded, password, type.nativeValue) == Argon2Native.OK;
  }

  public static class Builder {
    private final Version version;

    private int  t           = 3;
    private int  m           = 1 << 12;
    private int  parallelism = 1;
    private int  hashLength  = 32;
    private Type type        = Type.Argon2i;

    public Builder(Version version) {
      this.version = version;
    }

    /**
     * Type of Argon to use {@link Type#Argon2i} is the default.
     */
    public Builder type(Type type) {
      this.type = type;
      return this;
    }

    /**
     * Sets parallelism to {@param n} threads (default 1)
     */
    public Builder parallelism(int n) {
      this.parallelism = n;
      return this;
    }

    /**
     * Sets the memory usage of 2^{@param n} KiB (default 12)
     *
     * @param n This function accepts [0..30]. 0 is 1 KiB and 30 is 1 TiB.
     */
    public Builder memoryCost(int n) {
      if (n <  0) throw new IllegalArgumentException("n too small, minimum 0");
      if (n > 30) throw new IllegalArgumentException("n too high, maximum 30");
      this.m = 1 << n;
      return this;
    }

    /**
     * Sets the memory usage using the {@link MemoryCost} enum.
     */
    public Builder memoryCost(MemoryCost memoryCost) {
      return memoryCost(memoryCost.m);
    }

    /**
     * Sets the number of iterations to {@param n} (default = 3)
     */
    public Builder iterations(int n) {
      this.t = n;
      return this;
    }

    /**
     * Output hash length, default 32.
     */
    public Builder hashLength(int hashLength) {
      this.hashLength = hashLength;
      return this;
    }

    public Argon2 build() {
      return new Argon2(this);
    }
  }

  public Result hash(byte[] password, byte[] salt) throws Argon2Exception {
    StringBuffer encoded = new StringBuffer();
    byte[]       hash    = new byte[hashLength];
    int          result  = Argon2Native.hash(t, m, parallelism,
                                             password,
                                             salt,
                                             hash,
                                             encoded,
                                             type.nativeValue,
                                             version.nativeValue);

    if (result != Argon2Native.OK) {
      throw new Argon2Exception(result, Argon2Native.resultToString(result));
    }

    return new Result(encoded.toString(), hash);
  }

  public final class Result {
    private final String encoded;
    private final byte[] hash;

    private Result(String encoded, byte[] hash) {
      this.encoded = encoded;
      this.hash    = hash;
    }

    public String getEncoded() {
      return encoded;
    }

    public byte[] getHash() {
      return hash;
    }

    public String getHashHex() {
      return toHex(hash);
    }

    @Override
    public String toString() {
      return String.format(Locale.US,
                           "Type:           %s%n" +
                           "Iterations:     %d%n" +
                           "Memory:         %d KiB%n" +
                           "Parallelism:    %d%n" +
                           "Hash:           %s%n" +
                           "Encoded:        %s%n",
                           type,
                           t,
                           m,
                           parallelism,
                           getHashHex(),
                           encoded);
    }
  }

  private static String toHex(byte[] hash) {
    StringBuilder stringBuilder = new StringBuilder(hash.length * 2);
    for (byte b : hash) {
      stringBuilder.append(String.format(Locale.US, "%02x", b));
    }
    return stringBuilder.toString();
  }

}
