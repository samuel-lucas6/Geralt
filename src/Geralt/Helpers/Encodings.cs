using System.Buffers;
using static Interop.Libsodium;

namespace Geralt;

public static class Encodings
{
    public const string HexCharacterSet = "0123456789ABCDEFabcdef";
    public const string Base64CharacterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    public const string Base64UrlCharacterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
    public const string Base64FullCharacterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=";
    public const string HexIgnoreChars = ":- _./,%;";
    public const string Base64IgnoreChars = " \r\n";

    public enum Base64Variant
    {
        Original = 1,
        OriginalNoPadding = 3,
        Url = 5,
        UrlNoPadding = 7
    }

    public static void ToHex(Span<char> hex, ReadOnlySpan<byte> data)
    {
        Validation.EqualToSize(nameof(hex), hex.Length, GetToHexBufferSize(data));
        Sodium.Initialize();
        // libsodium includes a null byte terminator
        Span<byte> hexBuffer = GC.AllocateArray<byte>(hex.Length + 1, pinned: true);
        try {
            IntPtr ret = sodium_bin2hex(hexBuffer, (nuint)hexBuffer.Length, data, (nuint)data.Length);
            if (ret == IntPtr.Zero) { throw new FormatException("Error converting bytes to hex."); }
            for (int i = 0; i < hexBuffer.Length - 1; i++) {
                hex[i] = (char)hexBuffer[i];
            }
        }
        finally {
            SecureMemory.ZeroMemory(hexBuffer);
        }
    }

    public static int GetToHexBufferSize(ReadOnlySpan<byte> data)
    {
        Validation.NotEmpty(nameof(data), data.Length);
        return checked(data.Length * 2);
    }

    public static void FromHex(Span<byte> data, ReadOnlySpan<char> hex, ReadOnlySpan<char> ignoreChars = default)
    {
        Validation.EqualToSize(nameof(data), data.Length, GetFromHexBufferSize(hex, ignoreChars));
        Sodium.Initialize();
        Span<byte> hexBuffer = GC.AllocateArray<byte>(hex.Length, pinned: true);
        for (int i = 0; i < hex.Length; i++) {
            hexBuffer[i] = (byte)hex[i];
        }
        try {
            int ret = sodium_hex2bin(data, (nuint)data.Length, hexBuffer, (nuint)hexBuffer.Length, ignoreChars.ToString(), binaryLength: out _, hexEnd: null);
            if (ret != 0) { throw new FormatException("Unable to parse the hex string."); }
        }
        finally {
            SecureMemory.ZeroMemory(hexBuffer);
        }
    }

    public static int GetFromHexBufferSize(ReadOnlySpan<char> hex, ReadOnlySpan<char> ignoreChars = default)
    {
        if (ignoreChars.IsEmpty) {
            Validation.MultipleOfSize(nameof(hex), hex.Length, 2);
            return hex.Length / 2;
        }
        Validation.NotEmpty(nameof(hex), hex.Length);
        if (ignoreChars.ContainsAny(SearchValues.Create(HexCharacterSet))) {
            throw new ArgumentOutOfRangeException(nameof(ignoreChars), $"{nameof(ignoreChars)} cannot contain hex characters.");
        }
        int ignoreCharsCount = 0;
        foreach (char c in hex) {
            if (ignoreChars.Contains(c)) {
                ignoreCharsCount++;
            }
        }
        Validation.MultipleOfSize(nameof(hex), hex.Length - ignoreCharsCount, 2);
        return (hex.Length - ignoreCharsCount) / 2;
    }

    public static void ToBase64(Span<char> base64, ReadOnlySpan<byte> data, Base64Variant variant = Base64Variant.Original)
    {
        Validation.EqualToSize(nameof(base64), base64.Length, GetToBase64BufferSize(data, variant));
        Sodium.Initialize();
        // libsodium includes a null byte terminator
        Span<byte> base64Buffer = GC.AllocateArray<byte>(base64.Length + 1, pinned: true);
        try {
            IntPtr ret = sodium_bin2base64(base64Buffer, (nuint)base64Buffer.Length, data, (nuint)data.Length, (int)variant);
            if (ret == IntPtr.Zero) { throw new FormatException("Error converting bytes to Base64."); }
            for (int i = 0; i < base64Buffer.Length - 1; i++) {
                base64[i] = (char)base64Buffer[i];
            }
        }
        finally {
            SecureMemory.ZeroMemory(base64Buffer);
        }
    }

    public static int GetToBase64BufferSize(ReadOnlySpan<byte> data, Base64Variant variant = Base64Variant.Original)
    {
        Validation.NotEmpty(nameof(data), data.Length);
        // Remove the null byte terminator
        return sodium_base64_encoded_len((nuint)data.Length, (int)variant) - 1;
    }

    public static void FromBase64(Span<byte> data, ReadOnlySpan<char> base64, Base64Variant variant = Base64Variant.Original, ReadOnlySpan<char> ignoreChars = default)
    {
        Validation.EqualToSize(nameof(data), data.Length, GetFromBase64BufferSize(base64, variant, ignoreChars));
        Sodium.Initialize();
        Span<byte> base64Buffer = GC.AllocateArray<byte>(base64.Length, pinned: true);
        for (int i = 0; i < base64.Length; i++) {
            base64Buffer[i] = (byte)base64[i];
        }
        try {
            int ret = sodium_base642bin(data, (nuint)data.Length, base64Buffer, (nuint)base64Buffer.Length, ignoreChars.ToString(), binaryLength: out _, base64End: null, (int)variant);
            if (ret != 0) { throw new FormatException("Unable to parse the Base64 string."); }
        }
        finally {
            SecureMemory.ZeroMemory(base64Buffer);
        }
    }

    public static int GetFromBase64BufferSize(ReadOnlySpan<char> base64, Base64Variant variant = Base64Variant.Original, ReadOnlySpan<char> ignoreChars = default)
    {
        Validation.NotEmpty(nameof(base64), base64.Length);
        if (ignoreChars.IsEmpty) {
            if (variant is Base64Variant.Original or Base64Variant.Url) {
                Validation.MultipleOfSize(nameof(base64), base64.Length, 4);
            }
            else {
                if (base64.Length % 4 == 1) {
                    throw new ArgumentOutOfRangeException(nameof(base64), base64.Length, $"{nameof(base64)} without padding must be a valid length.");
                }
            }
        }
        int ignoreCharsCount = 0;
        if (!ignoreChars.IsEmpty) {
            if (ignoreChars.ContainsAny(SearchValues.Create(Base64FullCharacterSet))) {
                throw new ArgumentOutOfRangeException(nameof(ignoreChars), $"{nameof(ignoreChars)} cannot contain Base64 characters.");
            }
            foreach (char c in base64) {
                if (ignoreChars.Contains(c)) {
                    ignoreCharsCount++;
                }
            }
            if (base64.Length - ignoreCharsCount == 0) {
                throw new ArgumentOutOfRangeException(nameof(base64), $"{nameof(base64)} must contain characters that aren't ignored.");
            }
        }
        if (variant is Base64Variant.Original or Base64Variant.Url) {
            return checked((base64.Length - ignoreCharsCount - base64.Count('=')) * 3) / 4;
        }
        return checked((base64.Length - ignoreCharsCount) * 3) / 4;
    }
}
