using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace Geralt;

public static class Encodings
{
    private const string HexIgnoreChars = ":- ";
    private const string Base64IgnoreChars = " ";
    
    public enum Base64Variant
    {
        Original = 1,
        OriginalNoPadding = 3,
        Url = 5,
        UrlNoPadding = 7
    }
    
    public static unsafe string ToHex(ReadOnlySpan<byte> data)
    {
        Validation.NotEmpty(nameof(data), data.Length);
        Sodium.Initialise();
        ReadOnlySpan<byte> hex = stackalloc byte[data.Length * 2 + 1];
        fixed (byte* h = hex, b = data)
        {
            IntPtr ret = sodium_bin2hex(h, (nuint)hex.Length, b, (nuint)data.Length);
            return Marshal.PtrToStringAnsi(ret) ?? throw new FormatException("Error converting bytes to hex.");
        }
    }
    
    public static byte[] FromHex(string hex, string ignoreChars = HexIgnoreChars)
    {
        Validation.NotNullOrEmpty(nameof(hex), hex);
        Sodium.Initialise();
        var binary = new byte[hex.Length >> 1];
        int ret = sodium_hex2bin(binary, (nuint)binary.Length, hex, (nuint)hex.Length, ignoreChars, out nuint binaryLength, hexEnd: null);
        if (ret != 0) { throw new FormatException("Unable to parse the hex string."); }
        Array.Resize(ref binary, (int)binaryLength);
        return binary;
    }

    public static unsafe string ToBase64(ReadOnlySpan<byte> data, Base64Variant variant = Base64Variant.Original)
    {
        Validation.NotEmpty(nameof(data), data.Length);
        Sodium.Initialise();
        int base64MaxLength = sodium_base64_encoded_len((nuint)data.Length, (int)variant);
        Span<byte> base64 = stackalloc byte[base64MaxLength];
        fixed (byte* b = base64, d = data)
        {
            IntPtr ret = sodium_bin2base64(b, (nuint)base64MaxLength, d, (nuint)data.Length, (int)variant);
            return Marshal.PtrToStringAnsi(ret) ?? throw new FormatException("Error converting bytes to Base64.");
        }
    }

    public static byte[] FromBase64(string base64, Base64Variant variant = Base64Variant.Original, string ignoreChars = Base64IgnoreChars)
    {
        Validation.NotNullOrEmpty(nameof(base64), base64);
        Sodium.Initialise();
        var binary = new byte[base64.Length];
        int ret = sodium_base642bin(binary, (nuint)binary.Length, base64, (nuint)base64.Length, ignoreChars, out nuint binaryLength, base64End: null, (int)variant);
        if (ret != 0) { throw new FormatException("Unable to parse the Base64 string."); }
        Array.Resize(ref binary, (int)binaryLength);
        return binary;
    }
}