using static Interop.Libsodium;

namespace Geralt;

public static class Argon2id
{
    public const int KeySize = 32;
    public const int MinKeySize = KeySize;
    public const int SaltSize = crypto_pwhash_SALTBYTES;
    public const int MinIterations = crypto_pwhash_argon2id_OPSLIMIT_MIN;
    public const int MinMemorySize = 16777216;
    public const int MinHashSize = 93;
    public const int MaxHashSize = crypto_pwhash_STRBYTES;
    public const string HashPrefix = crypto_pwhash_argon2id_STRPREFIX;
    
    private enum Algorithm
    {
        Argon2id = crypto_pwhash_argon2id_ALG_ARGON2ID13,
        Argon2i = crypto_pwhash_argon2i_ALG_ARGON2I13
    }

    public static unsafe void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterations, int memorySize)
    {
        Validation.NotLessThanMin(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, MinKeySize);
        Validation.EqualToSize(nameof(salt), salt.Length, SaltSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialise();
        fixed (byte* ok = outputKeyingMaterial, p = password, s = salt)
        {
            int ret = crypto_pwhash(ok, (ulong)outputKeyingMaterial.Length, p, (ulong)password.Length, s, (ulong)iterations, (nuint)memorySize, (int)Algorithm.Argon2id);
            if (ret != 0) { throw new InsufficientMemoryException("Insufficient memory to perform key derivation."); }
        }
    }

    public static unsafe void ComputeHash(Span<byte> hash, ReadOnlySpan<byte> password, int iterations, int memorySize)
    {
        Validation.EqualToSize(nameof(hash), hash.Length, MaxHashSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialise();
        fixed (byte* h = hash, p = password)
        {
            int ret = crypto_pwhash_str_alg(h, p, (ulong)password.Length, (ulong)iterations, (nuint)memorySize, (int)Algorithm.Argon2id);
            if (ret != 0) { throw new InsufficientMemoryException("Insufficient memory to perform password hashing."); }
        }
    }
    
    public static unsafe bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> password)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Sodium.Initialise();
        fixed (byte* h = hash, p = password)
            return crypto_pwhash_str_verify(h, p, (ulong)password.Length) == 0;
    }

    public static unsafe bool NeedsRehash(ReadOnlySpan<byte> hash, int iterations, int memorySize)
    {
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialise();
        fixed (byte* h = hash)
        {
            int ret = crypto_pwhash_str_needs_rehash(h, (ulong)iterations, (nuint)memorySize);
            return ret == -1 ? throw new FormatException("Invalid password hash.") : ret == 1;
        }
    }
}