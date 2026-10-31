using System.Numerics;

namespace Geralt;

public static class Padme
{
    public const ulong MaxUnpaddedSize = 18302628885633695744;

    public static ulong GetPaddedSize(ulong unpaddedSize)
    {
        Validation.LessThanOrEqualTo(nameof(unpaddedSize), unpaddedSize, MaxUnpaddedSize);
        checked {
            if (unpaddedSize == 0) { return 0; }
            int exponent = 63 - BitOperations.LeadingZeroCount(unpaddedSize);
            int exponentBits = 64 - BitOperations.LeadingZeroCount((ulong)exponent);
            int zeroBits = exponent - exponentBits;
            ulong mask = ((ulong)1 << zeroBits) - 1;
            return (unpaddedSize + mask) & ~mask;
        }
    }

    public static ulong GetPaddingSize(ulong unpaddedSize)
    {
        return GetPaddedSize(unpaddedSize) - unpaddedSize;
    }
}
