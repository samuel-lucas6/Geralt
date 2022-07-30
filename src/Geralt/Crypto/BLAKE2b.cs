using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class BLAKE2b
{
    public const int HashSize = crypto_generichash_BYTES_MAX;
    public const int KeySize = crypto_generichash_KEYBYTES;
    public const int TagSize = crypto_generichash_BYTES;
    public const int SaltSize = crypto_generichash_blake2b_SALTBYTES;
    public const int PersonalSize = crypto_generichash_blake2b_PERSONALBYTES;
    public const int MinHashSize = crypto_generichash_BYTES_MIN;
    public const int MaxHashSize = crypto_generichash_BYTES_MAX;
    public const int MinKeySize = crypto_generichash_KEYBYTES;
    public const int MaxKeySize = crypto_generichash_KEYBYTES_MAX;

    public static unsafe void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Validation.NotEmpty(nameof(message), message.Length);
        Sodium.Initialise();
        fixed (byte* h = hash, m = message)
        {
            int ret = crypto_generichash_blake2b(h, (nuint)hash.Length, m, (ulong)message.Length, key: null, keyLength: (nuint)0);
            if (ret != 0) { throw new CryptographicException("Error computing hash."); }
        }
    }

    public static unsafe void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        Validation.SizeBetween(nameof(tag), tag.Length, MinHashSize, MaxHashSize);
        Validation.NotEmpty(nameof(message), message.Length);
        Validation.SizeBetween(nameof(key), key.Length, MinKeySize, MaxKeySize);
        Sodium.Initialise();
        fixed (byte* t = tag, m = message, k = key)
        {
            int ret = crypto_generichash_blake2b(t, (nuint)tag.Length, m, (ulong)message.Length, k, (nuint)key.Length);
            if (ret != 0) { throw new CryptographicException("Error computing tag."); }
        }
    }

    public static bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        Validation.SizeBetween(nameof(tag), tag.Length, MinHashSize, MaxHashSize);
        Validation.NotEmpty(nameof(message), message.Length);
        Validation.SizeBetween(nameof(key), key.Length, MinKeySize, MaxKeySize);
        Span<byte> computedTag = stackalloc byte[tag.Length];
        ComputeTag(computedTag, message, key);
        bool equal = ConstantTime.Equals(tag, computedTag);
        CryptographicOperations.ZeroMemory(computedTag);
        return equal;
    }

    public static unsafe void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> personalisation, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info = default)
    {
        Validation.SizeBetween(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, MinKeySize, MaxKeySize);
        Validation.SizeBetween(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, MinKeySize, MaxKeySize);
        Validation.EqualToSize(nameof(personalisation), personalisation.Length, PersonalSize);
        Validation.EqualToSize(nameof(salt), salt.Length, SaltSize);
        Sodium.Initialise();
        fixed (byte* ok = outputKeyingMaterial, ik = inputKeyingMaterial, p = personalisation, s = salt, i = info)
        {
            int ret = crypto_generichash_blake2b_salt_personal(ok, (nuint)outputKeyingMaterial.Length, i, (ulong)info.Length, ik, (nuint)inputKeyingMaterial.Length, s, p);
            if (ret != 0) { throw new CryptographicException("Error deriving key."); }
        }
    }
}