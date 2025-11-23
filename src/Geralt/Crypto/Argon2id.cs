using System.Text;
using static Interop.Libsodium;

namespace Geralt;

public static class Argon2id
{
    public const int KeySize = 32;
    public const int SaltSize = crypto_pwhash_argon2id_SALTBYTES;
    public const int HashSize = MaxHashSize;
    public const int MinKeySize = crypto_pwhash_argon2id_BYTES_MIN;
    public const int MinIterations = crypto_pwhash_argon2id_OPSLIMIT_MIN;
    public const int MinMemorySize = crypto_pwhash_argon2id_MEMLIMIT_MIN;
    private const int MinHashSize = 45; // With Argon2id, 45 characters according to CyberChef (e.g., $argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ$AKal+Q), 55 characters according to the PHC string format spec, and 93 when generated with libsodium
    private const int MaxHashSize = crypto_pwhash_argon2id_STRBYTES; // With Argon2id and no keyid/data, 198 characters according to the PHC string format spec (e.g., $argon2id$v=19$m=0000000000,t=0000000000,p=000$1111111111111111111111111111111111111111111111111111111111111111$22222222222222222222222222222222222222222222222222222222222222222222222222222222222222)
    private const string HashPrefix = crypto_pwhash_argon2id_STRPREFIX;

    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int memorySize)
    {
        Validation.NotLessThanMin(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, MinKeySize);
        Validation.EqualToSize(nameof(salt), salt.Length, SaltSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialize();
        int ret = crypto_pwhash(outputKeyingMaterial, (ulong)outputKeyingMaterial.Length, password, (ulong)password.Length, salt, (ulong)iterations, (nuint)memorySize, crypto_pwhash_argon2id_ALG_ARGON2ID13);
        if (ret != 0) { throw new InsufficientMemoryException("Insufficient memory to perform password-based key derivation."); }
    }

    public static void ComputeHash(Span<char> hash, ReadOnlySpan<byte> password, int iterations, int memorySize)
    {
        Validation.EqualToSize(nameof(hash), hash.Length, HashSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialize();
        Span<byte> hashBytes = stackalloc byte[HashSize];
        try {
            int ret = crypto_pwhash_str_alg(hashBytes, password, (ulong)password.Length, (ulong)iterations, (nuint)memorySize, crypto_pwhash_argon2id_ALG_ARGON2ID13);
            if (ret != 0) { throw new InsufficientMemoryException("Insufficient memory to perform password hashing."); }
            for (int i = 0; i < hashBytes.Length; i++) {
                hash[i] = (char)hashBytes[i];
            }
        }
        finally {
            SecureMemory.ZeroMemory(hashBytes);
        }
    }

    public static bool VerifyHash(ReadOnlySpan<char> hash, ReadOnlySpan<byte> password)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Span<byte> hashBytes = stackalloc byte[HashSize]; hashBytes.Clear();
        try {
            for (int i = 0; i < hash.Length; i++) {
                hashBytes[i] = (byte)hash[i];
            }
            ThrowIfInvalidHashPrefix(hashBytes);
            Sodium.Initialize();
            return crypto_pwhash_str_verify(hashBytes, password, (ulong)password.Length) == 0;
        }
        finally {
            SecureMemory.ZeroMemory(hashBytes);
        }
    }

    public static bool NeedsRehash(ReadOnlySpan<char> hash, int iterations, int memorySize)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Span<byte> hashBytes = stackalloc byte[HashSize]; hashBytes.Clear();
        try {
            for (int i = 0; i < hash.Length; i++) {
                hashBytes[i] = (byte)hash[i];
            }
            ThrowIfInvalidHashPrefix(hashBytes);
            Sodium.Initialize();
            int ret = crypto_pwhash_str_needs_rehash(hashBytes, (ulong)iterations, (nuint)memorySize);
            return ret == -1 ? throw new FormatException("Invalid password hash string.") : ret == 1;
        }
        finally {
            SecureMemory.ZeroMemory(hashBytes);
        }
    }

    private static void ThrowIfInvalidHashPrefix(ReadOnlySpan<byte> hashBytes)
    {
        if (!ConstantTime.Equals(hashBytes[..HashPrefix.Length], Encoding.ASCII.GetBytes(HashPrefix))) {
            throw new FormatException("Invalid password hash string prefix.");
        }
    }
}
