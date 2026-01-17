using static Interop.Libsodium;

namespace Geralt;

public static class Iso78164Padding
{
    public static void Pad(Span<byte> buffer, ReadOnlySpan<byte> data, int blockSize)
    {
        Validation.EqualToSize(nameof(buffer), buffer.Length, GetPaddedBufferSize(data, blockSize));
        Sodium.Initialize();
        data.CopyTo(buffer);
        int ret = sodium_pad(paddedBufferLength: out _, buffer, (nuint)data.Length, (nuint)blockSize, (nuint)buffer.Length);
        if (ret != 0) { throw new ArgumentOutOfRangeException(nameof(buffer), $"{nameof(buffer)} is not large enough."); }
    }

    public static int GetPaddedBufferSize(ReadOnlySpan<byte> data, int blockSize)
    {
        // data can be empty for Fill()
        Validation.GreaterThanZero(nameof(blockSize), blockSize);
        int paddingSize = blockSize - (data.Length % blockSize);
        return checked(data.Length + paddingSize);
    }

    public static void Fill(Span<byte> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Pad(buffer, ReadOnlySpan<byte>.Empty, buffer.Length);
    }

    public static int GetUnpaddedBufferSize(ReadOnlySpan<byte> paddedData, int blockSize)
    {
        Validation.NotEmpty(nameof(paddedData), paddedData.Length);
        Validation.GreaterThanZero(nameof(blockSize), blockSize);
        Sodium.Initialize();
        int ret = sodium_unpad(out nuint unpaddedSize, paddedData, (nuint)paddedData.Length, (nuint)blockSize);
        if (ret != 0) { throw new FormatException("Invalid padding."); }
        return (int)unpaddedSize;
    }
}
