using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalBLAKE2b : IDisposable
{
    public const int HashSize = BLAKE2b.HashSize;
    public const int KeySize = BLAKE2b.KeySize;
    public const int TagSize = BLAKE2b.TagSize;
    public const int BlockSize = BLAKE2b.BlockSize;
    public const int SaltSize = BLAKE2b.SaltSize;
    public const int PersonalizationSize = BLAKE2b.PersonalizationSize;
    public const int MinHashSize = BLAKE2b.MinHashSize;
    public const int MaxHashSize = BLAKE2b.MaxHashSize;
    public const int MinTagSize = BLAKE2b.MinTagSize;
    public const int MaxTagSize = BLAKE2b.MaxTagSize;
    public const int MinKeySize = BLAKE2b.MinKeySize;
    public const int MaxKeySize = BLAKE2b.MaxKeySize;

    private crypto_generichash_blake2b_state _state;
    private crypto_generichash_blake2b_state _cachedState;
    private int _hashSize;
    private bool _finalized;
    private bool _cached;
    private bool _disposed;

    public IncrementalBLAKE2b(int hashSize, ReadOnlySpan<byte> key = default, ReadOnlySpan<byte> personalization = default, ReadOnlySpan<byte> salt = default)
    {
        Sodium.Initialize();
        Reinitialize(hashSize, key, personalization, salt);
    }

    public void Reinitialize(int hashSize, ReadOnlySpan<byte> key = default, ReadOnlySpan<byte> personalization = default, ReadOnlySpan<byte> salt = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        Validation.Between(nameof(hashSize), hashSize, MinHashSize, MaxHashSize);
        if (key.Length != 0) { Validation.Between($"{nameof(key)}.{nameof(key.Length)}", key.Length, MinKeySize, MaxKeySize); }
        if (personalization.Length != 0) { Validation.EqualTo($"{nameof(personalization)}.{nameof(personalization.Length)}", personalization.Length, PersonalizationSize); }
        if (salt.Length != 0) { Validation.EqualTo($"{nameof(salt)}.{nameof(salt.Length)}", salt.Length, SaltSize); }
        int ret = (personalization.Length == 0 && salt.Length == 0)
            ? crypto_generichash_blake2b_init(ref _state, key, (nuint)key.Length, (nuint)hashSize)
            : crypto_generichash_blake2b_init_salt_personal(ref _state, key, (nuint)key.Length, (nuint)hashSize, salt.Length != 0 ? salt : new byte[SaltSize], personalization.Length != 0 ? personalization : new byte[PersonalizationSize]);
        if (ret != 0) { throw new CryptographicException("Error initializing hash function state."); }
        _hashSize = hashSize;
        _finalized = false;
    }

    public void Update(ReadOnlySpan<byte> message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing or restoring a cached state."); }
        int ret = crypto_generichash_blake2b_update(ref _state, message, (ulong)message.Length);
        if (ret != 0) { throw new CryptographicException("Error updating hash function state."); }
    }

    public void Finalize(Span<byte> hash)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing or restoring a cached state."); }
        Validation.EqualTo($"{nameof(hash)}.{nameof(hash.Length)}", hash.Length, _hashSize);
        int ret = crypto_generichash_blake2b_final(ref _state, hash, (nuint)hash.Length);
        if (ret != 0) { throw new CryptographicException("Error finalizing hash."); }
        _finalized = true;
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> hash)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing or restoring a cached state."); }
        Validation.EqualTo($"{nameof(hash)}.{nameof(hash.Length)}", hash.Length, _hashSize);
        Span<byte> computedHash = stackalloc byte[_hashSize];
        Finalize(computedHash);
        bool equal = ConstantTime.Equals(hash, computedHash);
        SecureMemory.ZeroMemory(computedHash);
        return equal;
    }

    public void CacheState()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        if (_finalized) { throw new InvalidOperationException("Cannot cache the state after finalizing without reinitializing."); }
        _cachedState = _state;
        _cached = true;
    }

    public void RestoreCachedState()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        if (!_cached) { throw new InvalidOperationException("Cannot restore the state when it has not been cached."); }
        _state = _cachedState;
        _finalized = false;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { return; }
        _state = default;
        _cachedState = default;
        _disposed = true;
    }
}
