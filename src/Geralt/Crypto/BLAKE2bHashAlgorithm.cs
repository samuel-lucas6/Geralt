using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class BLAKE2bHashAlgorithm : HashAlgorithm
{
    private crypto_generichash_blake2b_state _state;
    private readonly byte[]? _key;
    private readonly int _hashSize;
    private GCHandle _handle;
    
    public BLAKE2bHashAlgorithm(int hashSize, ReadOnlySpan<byte> key = default)
    {
        Validation.SizeBetween(nameof(hashSize), hashSize, BLAKE2b.MinHashSize, BLAKE2b.MaxHashSize);
        if (key != default) { Validation.SizeBetween(nameof(key), key.Length, BLAKE2b.MinKeySize, BLAKE2b.MaxKeySize); }
        Sodium.Initialise();
        _key = key == default ? null : key.ToArray();
        _handle = GCHandle.Alloc(_key, GCHandleType.Pinned);
        _hashSize = hashSize;
        Initialize();
    }

    public override unsafe void Initialize()
    {
        fixed (byte* k = _key)
        {
            int ret = crypto_generichash_init(ref _state, k, _key == null ? 0 : (nuint)_key.Length, (nuint)_hashSize);
            if (ret != 0) { throw new CryptographicException("Error initialising hash."); }
        }
    }

    protected override unsafe void HashCore(byte[] message, int offset, int size)
    {
        var buffer = new byte[size];
        Array.Copy(message, offset, buffer, destinationIndex: 0, buffer.Length);
        fixed (byte* b = buffer)
        {
            int ret = crypto_generichash_update(ref _state, b, (ulong)buffer.Length);
            if (ret != 0) { throw new CryptographicException("Error updating hash."); }
        }
    }

    protected override unsafe byte[] HashFinal()
    {
        var hash = new byte[_hashSize];
        fixed (byte* h = hash)
        {
            int ret = crypto_generichash_final(ref _state, h, (nuint)hash.Length);
            if (ret != 0) { throw new CryptographicException("Error finalising hash."); }
        }
        return hash;
    }

    protected override void Dispose(bool disposing)
    {
        CryptographicOperations.ZeroMemory(_key);
        _handle.Free();
        base.Dispose(disposing);
    }
}