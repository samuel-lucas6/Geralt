using System.Text;
using static Interop.Libsodium;

namespace Geralt;

public static class Argon2id
{
    public const int KeySize = 32;
    public const int SaltSize = crypto_pwhash_SALTBYTES;
    public const int MinKeySize = crypto_pwhash_BYTES_MIN;
    public const int MinIterations = crypto_pwhash_argon2id_OPSLIMIT_MIN;
    public const int MinMemorySize = crypto_pwhash_MEMLIMIT_MIN;
    public const int MinHashSize = 93;
    public const int MaxHashSize = crypto_pwhash_STRBYTES;
    private const string HashPrefix = crypto_pwhash_argon2id_STRPREFIX;

    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int memorySize)
    {
        Validation.NotLessThanMin(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, MinKeySize);
        Validation.EqualToSize(nameof(salt), salt.Length, SaltSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialize();
        int ret = crypto_pwhash(outputKeyingMaterial, (ulong)outputKeyingMaterial.Length, password, (ulong)password.Length, salt, (ulong)iterations, (nuint)memorySize, crypto_pwhash_argon2id_ALG_ARGON2ID13);
        if (ret != 0) { throw new InsufficientMemoryException("Insufficient memory to perform key derivation."); }
    }

    public static void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> password, int iterations, int memorySize)
    {
        Validation.EqualToSize(nameof(hash), hash.Length, MaxHashSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialize();
        int ret = crypto_pwhash_str_alg(hash, password, (ulong)password.Length, (ulong)iterations, (nuint)memorySize, crypto_pwhash_argon2id_ALG_ARGON2ID13);
        if (ret != 0) { throw new InsufficientMemoryException("Insufficient memory to perform password hashing."); }
    }

    public static bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> password)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        ThrowIfInvalidHashPrefix(hash);
        Sodium.Initialize();
        return crypto_pwhash_str_verify(hash, password, (ulong)password.Length) == 0;
    }

    public static bool NeedsRehash(ReadOnlySpan<byte> hash, int iterations, int memorySize)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        ThrowIfInvalidHashPrefix(hash);
        Sodium.Initialize();
        int ret = crypto_pwhash_str_needs_rehash(hash, (ulong)iterations, (nuint)memorySize);
        return ret == -1 ? throw new FormatException("Invalid encoded password hash.") : ret == 1;
    }

    private static void ThrowIfInvalidHashPrefix(ReadOnlySpan<byte> hash)
    {
        if (!ConstantTime.Equals(hash[..HashPrefix.Length], Encoding.UTF8.GetBytes(HashPrefix))) {
            throw new FormatException("Invalid encoded password hash prefix.");
        }
    }
}
