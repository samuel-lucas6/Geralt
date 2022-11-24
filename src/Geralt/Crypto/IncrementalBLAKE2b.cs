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

    public IncrementalBLAKE2b(int hashSize, ReadOnlySpan<byte> key = default)
    {
        Validation.SizeBetween(nameof(hashSize), hashSize, MinHashSize, MaxHashSize);
        if (key != default) { Validation.SizeBetween(nameof(key), key.Length, MinKeySize, MaxKeySize); }
        Sodium.Initialise();
        _hashSize = hashSize;
        Initialize(key);
    }

    private unsafe void Initialize(ReadOnlySpan<byte> key)
    {
        fixed (byte* k = key)
        {
            int ret = crypto_generichash_init(ref _state, k, (nuint)key.Length, (nuint)_hashSize);
            if (ret != 0) { throw new CryptographicException("Error initialising hash."); }
        }
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        fixed (byte* m = message)
        {
            int ret = crypto_generichash_update(ref _state, m, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating hash."); }
        }
    }

    public unsafe void Finalize(Span<byte> hash)
    {
        Validation.EqualToSize(nameof(hash), hash.Length, _hashSize);
        fixed (byte* h = hash)
        {
            int ret = crypto_generichash_final(ref _state, h, (nuint)hash.Length);
            if (ret != 0) { throw new CryptographicException("Error finalising hash."); }
        }
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}