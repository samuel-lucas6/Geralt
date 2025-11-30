using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalBLAKE2b : IDisposable
{
    public const int HashSize = BLAKE2b.HashSize;
    public const int KeySize = BLAKE2b.KeySize;
    public const int TagSize = BLAKE2b.TagSize;
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

    public IncrementalBLAKE2b(int hashSize, ReadOnlySpan<byte> key = default)
    {
        Sodium.Initialize();
        Reinitialize(hashSize, key);
    }

    public void Reinitialize(int hashSize, ReadOnlySpan<byte> key = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        Validation.SizeBetween(nameof(hashSize), hashSize, MinHashSize, MaxHashSize);
        if (key.Length != 0) { Validation.SizeBetween(nameof(key), key.Length, MinKeySize, MaxKeySize); }
        int ret = crypto_generichash_blake2b_init(ref _state, key, (nuint)key.Length, (nuint)hashSize);
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
        Validation.EqualToSize(nameof(hash), hash.Length, _hashSize);
        int ret = crypto_generichash_blake2b_final(ref _state, hash, (nuint)hash.Length);
        if (ret != 0) { throw new CryptographicException("Error finalizing hash."); }
        _finalized = true;
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> hash)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalBLAKE2b)); }
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice without reinitializing or restoring a cached state."); }
        Validation.EqualToSize(nameof(hash), hash.Length, _hashSize);
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
