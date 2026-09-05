using System.Numerics;

namespace Geralt;

public static class Padme
{
    public static ulong GetPaddedLength(ulong length)
    {
        if (length == 0) { return 0; }
        int exponent = 63 - BitOperations.LeadingZeroCount(length);
        int exponentBits = 64 - BitOperations.LeadingZeroCount((ulong)exponent);
        int zeroBits = exponent - exponentBits;
        ulong mask = ((ulong)1 << zeroBits) - 1;
        return checked((length + mask) & ~mask);
    }

    public static ulong GetPaddingLength(ulong length)
    {
        return GetPaddedLength(length) - length;
    }
}
