using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class Poly1305
{
    public const int KeySize = crypto_onetimeauth_KEYBYTES;
    public const int TagSize = crypto_onetimeauth_BYTES;
    
    public static unsafe void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> oneTimeKey)
    {
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        Validation.EqualToSize(nameof(oneTimeKey), oneTimeKey.Length, KeySize);
        Sodium.Initialise();
        fixed (byte* t = tag, m = message, k = oneTimeKey)
        {
            int ret = crypto_onetimeauth(t, m, (ulong)message.Length, k);
            if (ret != 0) { throw new CryptographicException("Error computing tag."); }
        }
    }

    public static unsafe bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> oneTimeKey)
    {
        Validation.EqualToSize(nameof(tag), tag.Length, TagSize);
        Validation.EqualToSize(nameof(oneTimeKey), oneTimeKey.Length, KeySize);
        Sodium.Initialise();
        fixed (byte* t = tag, m = message, k = oneTimeKey)
            return crypto_onetimeauth_verify(t, m, (ulong)message.Length, k) == 0;
    }
}