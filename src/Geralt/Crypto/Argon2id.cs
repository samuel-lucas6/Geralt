﻿using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace Geralt;

public static class Argon2id
{
    public const int KeySize = 32;
    public const int SaltSize = crypto_pwhash_SALTBYTES;
    public const int MinKeySize = crypto_pwhash_BYTES_MIN;
    public const int MinIterations = crypto_pwhash_argon2id_OPSLIMIT_MIN;
    public const int MinMemorySize = crypto_pwhash_MEMLIMIT_MIN;
    public const int MinHashSize = 93; // Smallest possible Argon2id string that libsodium can generate
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

    public static string ComputeHash(ReadOnlySpan<byte> password, int iterations, int memorySize)
    {
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        Sodium.Initialize();
        nint hash = Marshal.AllocHGlobal(MaxHashSize);
        try {
            int ret = crypto_pwhash_str_alg(hash, password, (ulong)password.Length, (ulong)iterations, (nuint)memorySize, crypto_pwhash_argon2id_ALG_ARGON2ID13);
            if (ret != 0) { throw new InsufficientMemoryException("Insufficient memory to perform password hashing."); }
            return Marshal.PtrToStringAnsi(hash)!;
        }
        finally {
            Marshal.FreeHGlobal(hash);
        }
    }

    public static bool VerifyHash(string hash, ReadOnlySpan<byte> password)
    {
        Validation.NotNull(nameof(hash), hash);
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        ThrowIfInvalidHashPrefix(hash);
        Sodium.Initialize();
        return crypto_pwhash_str_verify(hash, password, (ulong)password.Length) == 0;
    }

    public static bool NeedsRehash(string hash, int iterations, int memorySize)
    {
        Validation.NotNull(nameof(hash), hash);
        Validation.SizeBetween(nameof(hash), hash.Length, MinHashSize, MaxHashSize);
        Validation.NotLessThanMin(nameof(iterations), iterations, MinIterations);
        Validation.NotLessThanMin(nameof(memorySize), memorySize, MinMemorySize);
        ThrowIfInvalidHashPrefix(hash);
        Sodium.Initialize();
        int ret = crypto_pwhash_str_needs_rehash(hash, (ulong)iterations, (nuint)memorySize);
        return ret == -1 ? throw new FormatException("Invalid encoded password hash.") : ret == 1;
    }

    private static void ThrowIfInvalidHashPrefix(string hash)
    {
        if (!hash.StartsWith(HashPrefix)) {
            throw new FormatException("Invalid encoded password hash prefix.");
        }
    }
}
