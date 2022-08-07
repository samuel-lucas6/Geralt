using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public class BLAKE2bHashAlgorithm : HashAlgorithm
{
    private IntPtr _state;
    private byte[]? _key;
    private readonly int _hashSize;
    private GCHandle _handle;
    
    public BLAKE2bHashAlgorithm(int hashSize, ReadOnlySpan<byte> key = default)
    {
        Validation.SizeBetween(nameof(hashSize), hashSize, BLAKE2b.MinHashSize, BLAKE2b.MaxHashSize);
        if (key != default) { Validation.SizeBetween(nameof(key), key.Length, BLAKE2b.MinKeySize, BLAKE2b.MaxKeySize); }
        Sodium.Initialise();
        _state = Marshal.AllocHGlobal(Marshal.SizeOf<crypto_generichash_blake2b_state>());
        _key = key == default ? null : key.ToArray();
        _handle = GCHandle.Alloc(_key, GCHandleType.Pinned);
        _hashSize = hashSize;
        Initialize();
    }

    public sealed override void Initialize()
    {
        int ret = crypto_generichash_init(_state, _key, _key == null ? (nuint)0 : (nuint)_key.Length, (nuint)_hashSize);
        if (ret != 0) { throw new CryptographicException("Error initialising hash."); }
    }

    protected override void HashCore(byte[] message, int offset, int size)
    {
        var buffer = Arrays.Slice(message, offset, size);
        int ret = crypto_generichash_update(_state, buffer, (ulong)buffer.Length);
        if (ret != 0) { throw new CryptographicException("Error updating hash."); }
    }

    protected override byte[] HashFinal()
    {
        var hash = new byte[_hashSize];
        int ret = crypto_generichash_final(_state, hash, (nuint)hash.Length);
        if (ret != 0) { throw new CryptographicException("Error finalising hash."); }
        return hash;
    }

    protected override void Dispose(bool disposing)
    {
        CryptographicOperations.ZeroMemory(_key);
        _handle.Free();
        base.Dispose(disposing);
    }

    ~BLAKE2bHashAlgorithm()
    {
        Marshal.FreeHGlobal(_state);
    }
}