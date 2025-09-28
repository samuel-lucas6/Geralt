using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class Poly1305
{
    public const int KeySize = crypto_onetimeauth_KEYBYTES;
    public const int TagSize = crypto_onetimeauth_BYTES;
    public const int BlockSize = 16;

    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> oneTimeKey)
    {
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        Validation.EqualToSize(nameof(oneTimeKey), oneTimeKey.Length, KeySize);
        Sodium.Initialize();
        int ret = crypto_onetimeauth(tag, message, (ulong)message.Length, oneTimeKey);
        if (ret != 0) { throw new CryptographicException("Error computing tag."); }
    }

    public static bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> oneTimeKey)
    {
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        Validation.EqualToSize(nameof(oneTimeKey), oneTimeKey.Length, KeySize);
        Sodium.Initialize();
        return crypto_onetimeauth_verify(tag, message, (ulong)message.Length, oneTimeKey) == 0;
    }
}
