package org.signal.argon2;

/**
 * Some useful values for use in the {@link Argon2.Builder#memoryCost(MemoryCost)} method for readability.
 */
public enum MemoryCost {
  KiB_8(3),
  KiB_16(4),
  KiB_32(5),
  KiB_64(6),
  KiB_128(7),
  KiB_256(8),
  KiB_512(9),
  MiB_1(10),
  MiB_2(11),
  MiB_4(12),
  MiB_8(13),
  MiB_16(14),
  MiB_32(15),
  MiB_64(16),
  MiB_128(17);

  int m;

  MemoryCost(int m) {
    this.m = m;
  }

  /** Number of bytes */
  int toBytes() {
    return 1 << (m + 10);
  }
}
