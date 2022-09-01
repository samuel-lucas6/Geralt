using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Geralt;

public sealed class BLAKE2bHashAlgorithm : HashAlgorithm
{
    private IncrementalBLAKE2b _blake2b;
    private readonly byte[]? _key;
    private readonly int _hashSize;
    private GCHandle _handle;
    
    public BLAKE2bHashAlgorithm(int hashSize, ReadOnlySpan<byte> key = default)
    {
        _blake2b = new IncrementalBLAKE2b(hashSize, key);
        _key = key == default ? null : key.ToArray();
        _handle = GCHandle.Alloc(_key, GCHandleType.Pinned);
        _hashSize = hashSize;
    }

    public override void Initialize()
    {
        _blake2b = new IncrementalBLAKE2b(_hashSize, _key);
    }

    protected override void HashCore(byte[] message, int offset, int size)
    {
        var buffer = new byte[size];
        Array.Copy(message, offset, buffer, destinationIndex: 0, buffer.Length);
        _blake2b.Update(buffer);
    }

    protected override byte[] HashFinal()
    {
        var hash = new byte[_hashSize];
        _blake2b.Finalize(hash);
        return hash;
    }

    protected override void Dispose(bool disposing)
    {
        CryptographicOperations.ZeroMemory(_key);
        _handle.Free();
        _blake2b.Dispose();
        base.Dispose(disposing);
    }
}