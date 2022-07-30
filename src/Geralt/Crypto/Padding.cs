using static Interop.Libsodium;

namespace Geralt;

public static class Padding
{
    public static unsafe void Pad(Span<byte> buffer, ReadOnlySpan<byte> data, int blockSize)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, GetPaddedLength(data.Length, blockSize));
        Validation.GreaterThanZero(nameof(blockSize), blockSize);
        Sodium.Initialise();
        data.CopyTo(buffer);
        fixed (byte* b = buffer)
        {
            int ret = sodium_pad(out nuint _, b, (nuint)data.Length, (nuint)blockSize, (nuint)buffer.Length);
            if (ret != 0) { throw new ArgumentOutOfRangeException(nameof(buffer), $"{nameof(buffer)} is not large enough."); }
        }
    }
    
    public static int GetPaddedLength(int unpaddedLength, int blockSize)
    {
        Validation.NotLessThanMin(nameof(unpaddedLength), unpaddedLength, minSize: 0);
        Validation.GreaterThanZero(nameof(blockSize), blockSize);
        int paddingLength = blockSize - unpaddedLength % blockSize;
        if (paddingLength > int.MaxValue - unpaddedLength) { throw new ArgumentOutOfRangeException(nameof(blockSize), "The amount of padding is too large."); }
        return unpaddedLength + paddingLength;
    }

    public static unsafe int GetUnpaddedLength(ReadOnlySpan<byte> paddedData, int blockSize)
    {
        Validation.NotEmpty(nameof(paddedData), paddedData.Length);
        Validation.GreaterThanZero(nameof(blockSize), blockSize);
        Sodium.Initialise();
        fixed (byte* p = paddedData)
        {
            int ret = sodium_unpad(out nuint unpaddedLength, p, (nuint)paddedData.Length, (nuint)blockSize);
            if (ret != 0) { throw new FormatException("Incorrect padding."); }
            return (int)unpaddedLength;
        }
    }
}