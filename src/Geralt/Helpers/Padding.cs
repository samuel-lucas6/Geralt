using static Interop.Libsodium;

namespace Geralt;

public static class Padding
{
    public static void Pad(Span<byte> buffer, ReadOnlySpan<byte> data, int blockSize)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, GetPaddedLength(data.Length, blockSize));
        Sodium.Initialize();
        data.CopyTo(buffer);
        int ret = sodium_pad(out nuint _, buffer, (nuint)data.Length, (nuint)blockSize, (nuint)buffer.Length);
        if (ret != 0) { throw new ArgumentOutOfRangeException(nameof(buffer), $"{nameof(buffer)} is not large enough."); }
    }

    public static int GetPaddedLength(int unpaddedLength, int blockSize)
    {
        Validation.NotLessThanMin(nameof(unpaddedLength), unpaddedLength, minSize: 0);
        Validation.GreaterThanZero(nameof(blockSize), blockSize);
        int paddingLength = blockSize - unpaddedLength % blockSize;
        if (paddingLength > int.MaxValue - unpaddedLength) { throw new ArgumentOutOfRangeException(nameof(blockSize), "The amount of padding is too large."); }
        return unpaddedLength + paddingLength;
    }

    public static void Fill(Span<byte> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Pad(buffer, ReadOnlySpan<byte>.Empty, buffer.Length);
    }

    public static int GetUnpaddedLength(ReadOnlySpan<byte> paddedData, int blockSize)
    {
        Validation.NotEmpty(nameof(paddedData), paddedData.Length);
        Validation.GreaterThanZero(nameof(blockSize), blockSize);
        Sodium.Initialize();
        int ret = sodium_unpad(out nuint unpaddedLength, paddedData, (nuint)paddedData.Length, (nuint)blockSize);
        if (ret != 0) { throw new FormatException("Incorrect padding."); }
        return (int)unpaddedLength;
    }
}
