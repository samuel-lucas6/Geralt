using System.Buffers;
using System.Security.Cryptography;
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
    private const int MaxStackSize = 1024;

    public enum Base64Variant
    {
        Original = 1,
        OriginalNoPadding = 3,
        Url = 5,
        UrlNoPadding = 7
    }

    public static void ToHex(Span<char> hex, ReadOnlySpan<byte> data)
    {
        Validation.EqualTo($"{nameof(hex)}.{nameof(hex.Length)}", hex.Length, GetToHexBufferSize(data));
        Sodium.Initialize();
        // libsodium includes a null byte terminator
        int hexBufferSize = hex.Length + 1;
        Span<byte> hexBuffer = hexBufferSize <= MaxStackSize ? stackalloc byte[hexBufferSize] : GC.AllocateArray<byte>(hexBufferSize, pinned: true);
        try {
            IntPtr ret = sodium_bin2hex(hexBuffer, (nuint)hexBuffer.Length, data, (nuint)data.Length);
            if (ret == IntPtr.Zero) { throw new CryptographicException("Error converting bytes to hex."); }
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
        Validation.EqualTo($"{nameof(data)}.{nameof(data.Length)}", data.Length, GetFromHexBufferSize(hex, ignoreChars));
        Sodium.Initialize();
        Span<byte> hexBuffer = hex.Length <= MaxStackSize ? stackalloc byte[hex.Length] : GC.AllocateArray<byte>(hex.Length, pinned: true);
        try {
            for (int i = 0; i < hex.Length; i++) {
                hexBuffer[i] = (byte)hex[i];
            }
            int ret = sodium_hex2bin(data, (nuint)data.Length, hexBuffer, (nuint)hexBuffer.Length, ignoreChars.ToString(), binaryLength: out _, hexEnd: null);
            if (ret != 0) { throw new FormatException("Invalid hex string."); }
        }
        finally {
            SecureMemory.ZeroMemory(hexBuffer);
        }
    }

    public static int GetFromHexBufferSize(ReadOnlySpan<char> hex, ReadOnlySpan<char> ignoreChars = default)
    {
        Validation.NotEmpty(nameof(hex), hex.Length);
        int lengthMinusIgnoredChars = hex.Length, allAscii = 0;
        foreach (char c in hex) {
            if (ignoreChars.Length != 0 && ignoreChars.Contains(c)) {
                lengthMinusIgnoredChars--;
            }
            allAscii |= c >> 7;
        }
        if (allAscii != 0) { throw new ArgumentException($"{nameof(hex)} cannot contain non-ASCII characters.", nameof(hex)); }
        if (ignoreChars.Length != 0) {
            if (ignoreChars.ContainsAny(SearchValues.Create(HexCharacterSet))) {
                throw new ArgumentException($"{nameof(ignoreChars)} cannot contain hex characters.", nameof(ignoreChars));
            }
            if (lengthMinusIgnoredChars == 0) {
                throw new ArgumentException($"{nameof(hex)} must contain characters that aren't ignored.", nameof(hex));
            }
        }
        Validation.MultipleOf($"{nameof(hex)}.{nameof(hex.Length)}", lengthMinusIgnoredChars, 2);
        return lengthMinusIgnoredChars / 2;
    }

    public static void ToBase64(Span<char> base64, ReadOnlySpan<byte> data, Base64Variant variant = Base64Variant.Original)
    {
        Validation.EqualTo($"{nameof(base64)}.{nameof(base64.Length)}", base64.Length, GetToBase64BufferSize(data, variant));
        Sodium.Initialize();
        // libsodium includes a null byte terminator
        int base64BufferSize = base64.Length + 1;
        Span<byte> base64Buffer = base64BufferSize <= MaxStackSize ? stackalloc byte[base64BufferSize] : GC.AllocateArray<byte>(base64BufferSize, pinned: true);
        try {
            IntPtr ret = sodium_bin2base64(base64Buffer, (nuint)base64Buffer.Length, data, (nuint)data.Length, (int)variant);
            if (ret == IntPtr.Zero) { throw new CryptographicException("Error converting bytes to Base64."); }
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
        return checked((int)sodium_base64_encoded_len((nuint)data.Length, (int)variant) - 1);
    }

    public static void FromBase64(Span<byte> data, ReadOnlySpan<char> base64, Base64Variant variant = Base64Variant.Original, ReadOnlySpan<char> ignoreChars = default)
    {
        Validation.EqualTo($"{nameof(data)}.{nameof(data.Length)}", data.Length, GetFromBase64BufferSize(base64, variant, ignoreChars));
        Sodium.Initialize();
        Span<byte> base64Buffer = base64.Length <= MaxStackSize ? stackalloc byte[base64.Length] : GC.AllocateArray<byte>(base64.Length, pinned: true);
        try {
            for (int i = 0; i < base64.Length; i++) {
                base64Buffer[i] = (byte)base64[i];
            }
            int ret = sodium_base642bin(data, (nuint)data.Length, base64Buffer, (nuint)base64Buffer.Length, ignoreChars.ToString(), binaryLength: out _, base64End: null, (int)variant);
            if (ret != 0) { throw new FormatException("Invalid Base64 string."); }
        }
        finally {
            SecureMemory.ZeroMemory(base64Buffer);
        }
    }

    public static int GetFromBase64BufferSize(ReadOnlySpan<char> base64, Base64Variant variant = Base64Variant.Original, ReadOnlySpan<char> ignoreChars = default)
    {
        Validation.NotEmpty(nameof(base64), base64.Length);
        int lengthMinusIgnoredChars = base64.Length, allAscii = 0;
        foreach (char c in base64) {
            if (ignoreChars.Length != 0 && ignoreChars.Contains(c)) {
                lengthMinusIgnoredChars--;
            }
            allAscii |= c >> 7;
        }
        if (allAscii != 0) { throw new ArgumentException($"{nameof(base64)} cannot contain non-ASCII characters.", nameof(base64)); }
        if (ignoreChars.Length != 0) {
            if (ignoreChars.ContainsAny(SearchValues.Create(Base64FullCharacterSet))) {
                throw new ArgumentException($"{nameof(ignoreChars)} cannot contain Base64 characters.", nameof(ignoreChars));
            }
            if (lengthMinusIgnoredChars == 0) {
                throw new ArgumentException($"{nameof(base64)} must contain characters that aren't ignored.", nameof(base64));
            }
        }
        if (variant is Base64Variant.Original or Base64Variant.Url) {
            Validation.MultipleOf($"{nameof(base64)}.{nameof(base64.Length)}", lengthMinusIgnoredChars, 4);
            lengthMinusIgnoredChars -= base64.Count('=');
        }
        else {
            if (lengthMinusIgnoredChars % 4 == 1) {
                throw new ArgumentOutOfRangeException(nameof(base64), base64.Length, $"{nameof(base64)} without padding must be a valid length.");
            }
        }
        return checked(lengthMinusIgnoredChars * 3) / 4;
    }
}
