using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public static class BLAKE2b
{
    public const int HashSize = crypto_generichash_blake2b_BYTES;
    public const int KeySize = crypto_generichash_blake2b_KEYBYTES;
    public const int TagSize = crypto_generichash_blake2b_BYTES;
    public const int SaltSize = crypto_generichash_blake2b_SALTBYTES;
    public const int PersonalizationSize = crypto_generichash_blake2b_PERSONALBYTES;
    public const int MinHashSize = crypto_generichash_blake2b_BYTES_MIN;
    public const int MaxHashSize = crypto_generichash_blake2b_BYTES_MAX;
    public const int MinTagSize = MinHashSize;
    public const int MaxTagSize = MaxHashSize;
    public const int MinKeySize = crypto_generichash_blake2b_KEYBYTES_MIN;
    public const int MaxKeySize = crypto_generichash_blake2b_KEYBYTES_MAX;

    public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> message)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Sodium.Initialize();
        int ret = crypto_generichash_blake2b(hash, (nuint)hash.Length, message, (ulong)message.Length, key: ReadOnlySpan<byte>.Empty, keyLength: 0);
        if (ret != 0) { throw new CryptographicException("Error computing hash."); }
    }

    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        Validation.SizeBetween(nameof(tag), tag.Length, MinTagSize, MaxTagSize);
        Validation.SizeBetween(nameof(key), key.Length, MinKeySize, MaxKeySize);
        Sodium.Initialize();
        int ret = crypto_generichash_blake2b(tag, (nuint)tag.Length, message, (ulong)message.Length, key, (nuint)key.Length);
        if (ret != 0) { throw new CryptographicException("Error computing tag."); }
    }

    public static bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        Validation.SizeBetween(nameof(tag), tag.Length, MinTagSize, MaxTagSize);
        Validation.SizeBetween(nameof(key), key.Length, MinKeySize, MaxKeySize);
        Span<byte> computedTag = stackalloc byte[tag.Length];
        ComputeTag(computedTag, message, key);
        bool equal = ConstantTime.Equals(tag, computedTag);
        SecureMemory.ZeroMemory(computedTag);
        return equal;
    }

    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> personalization, ReadOnlySpan<byte> salt = default, ReadOnlySpan<byte> info = default)
    {
        Validation.SizeBetween(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, MinKeySize, MaxKeySize);
        Validation.SizeBetween(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, MinKeySize, MaxKeySize);
        Validation.EqualToSize(nameof(personalization), personalization.Length, PersonalizationSize);
        if (salt.Length != 0) { Validation.EqualToSize(nameof(salt), salt.Length, SaltSize); }
        Sodium.Initialize();
        int ret = crypto_generichash_blake2b_salt_personal(outputKeyingMaterial, (nuint)outputKeyingMaterial.Length, info, (ulong)info.Length, inputKeyingMaterial, (nuint)inputKeyingMaterial.Length, salt.Length != 0 ? salt : new byte[SaltSize], personalization);
        if (ret != 0) { throw new CryptographicException("Error deriving key."); }
    }
}
