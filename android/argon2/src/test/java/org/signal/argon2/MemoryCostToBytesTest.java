package org.signal.argon2;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public final class MemoryCostToBytesTest {

  private final MemoryCost memoryCost;
  private final int        expectedBytes;

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{

      { MemoryCost.KiB_8, 8 * 1024 },
      { MemoryCost.KiB_16, 16 * 1024 },
      { MemoryCost.KiB_32, 32 * 1024 },
      { MemoryCost.KiB_64, 64 * 1024 },
      { MemoryCost.KiB_128, 128 * 1024 },
      { MemoryCost.KiB_256, 256 * 1024 },
      { MemoryCost.KiB_512, 512 * 1024 },

      { MemoryCost.MiB_1, 1024 * 1024 },
      { MemoryCost.MiB_2, 2 * 1024 * 1024 },
      { MemoryCost.MiB_4, 4 * 1024 * 1024 },
      { MemoryCost.MiB_8, 8 * 1024 * 1024 },
      { MemoryCost.MiB_16, 16 * 1024 * 1024 },
      { MemoryCost.MiB_32, 32 * 1024 * 1024 },
      { MemoryCost.MiB_64, 64 * 1024 * 1024 },
      { MemoryCost.MiB_128, 128 * 1024 * 1024 }
    });
  }

  public MemoryCostToBytesTest(MemoryCost memoryCost, int expectedBytes) {
    this.memoryCost    = memoryCost;
    this.expectedBytes = expectedBytes;
  }

  @Test
  public void toBytes() {
    assertEquals(expectedBytes, memoryCost.toBytes());
  }
}
