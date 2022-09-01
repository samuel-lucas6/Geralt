using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalBLAKE2b : IDisposable
{
    private crypto_generichash_blake2b_state _state;
    private readonly int _hashSize;

    public IncrementalBLAKE2b(int hashSize, ReadOnlySpan<byte> key = default)
    {
        Validation.SizeBetween(nameof(hashSize), hashSize, BLAKE2b.MinHashSize, BLAKE2b.MaxHashSize);
        if (key != default) { Validation.SizeBetween(nameof(key), key.Length, BLAKE2b.MinKeySize, BLAKE2b.MaxKeySize); }
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