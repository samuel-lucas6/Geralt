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
    public const int MinTagSize = MinHashSize;
    public const int MaxTagSize = MaxHashSize;
    public const int MinKeySize = BLAKE2b.MinKeySize;
    public const int MaxKeySize = BLAKE2b.MaxKeySize;

    private crypto_generichash_blake2b_state _state;
    private readonly int _hashSize;
    private bool _finalized;

    public IncrementalBLAKE2b(int hashSize, ReadOnlySpan<byte> key = default)
    {
        Validation.SizeBetween(nameof(hashSize), hashSize, MinHashSize, MaxHashSize);
        if (key.Length != 0) { Validation.SizeBetween(nameof(key), key.Length, MinKeySize, MaxKeySize); }
        Sodium.Initialize();
        _hashSize = hashSize;
        _finalized = false;
        Initialize(key);
    }

    private unsafe void Initialize(ReadOnlySpan<byte> key)
    {
        fixed (byte* k = key)
        {
            int ret = crypto_generichash_init(ref _state, k, (nuint)key.Length, (nuint)_hashSize);
            if (ret != 0) { throw new CryptographicException("Error initializing hash function state."); }
        }
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot update after finalizing."); }
        fixed (byte* m = message)
        {
            int ret = crypto_generichash_update(ref _state, m, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating hash function state."); }
        }
    }

    public unsafe void Finalize(Span<byte> hash)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice."); }
        Validation.EqualToSize(nameof(hash), hash.Length, _hashSize);
        _finalized = true;
        fixed (byte* h = hash)
        {
            int ret = crypto_generichash_final(ref _state, h, (nuint)hash.Length);
            if (ret != 0) { throw new CryptographicException("Error finalizing hash."); }
        }
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> hash)
    {
        if (_finalized) { throw new InvalidOperationException("Cannot finalize twice."); }
        Validation.EqualToSize(nameof(hash), hash.Length, _hashSize);
        Span<byte> computedHash = stackalloc byte[_hashSize];
        Finalize(computedHash);
        bool equal = ConstantTime.Equals(hash, computedHash);
        CryptographicOperations.ZeroMemory(computedHash);
        return equal;
    }

    public void Dispose()
    {
    }
}
