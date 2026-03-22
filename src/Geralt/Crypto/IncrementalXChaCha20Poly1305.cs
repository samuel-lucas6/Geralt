using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalXChaCha20Poly1305 : IDisposable
{
    public const int KeySize = crypto_secretstream_xchacha20poly1305_KEYBYTES;
    public const int HeaderSize = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    public const int TagSize = crypto_secretstream_xchacha20poly1305_ABYTES;

    private crypto_secretstream_xchacha20poly1305_state _state;
    private GCHandle _stateHandle;
    private bool _encryption;
    private bool _finalized;
    private bool _disposed;

    public enum ChunkFlag
    {
        Message = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
        Boundary = crypto_secretstream_xchacha20poly1305_TAG_PUSH,
        Rekey = crypto_secretstream_xchacha20poly1305_TAG_REKEY,
        Final = crypto_secretstream_xchacha20poly1305_TAG_FINAL
    }

    public IncrementalXChaCha20Poly1305(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        Sodium.Initialize();
        _stateHandle = GCHandle.Alloc(_state,  GCHandleType.Pinned);
        Reinitialize(header, key, encryption);
    }

    public void Reinitialize(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        Validation.EqualTo($"{nameof(header)}.{nameof(header.Length)}", header.Length, HeaderSize);
        Validation.EqualTo($"{nameof(key)}.{nameof(key.Length)}", key.Length, KeySize);
        int ret = _encryption
            ? crypto_secretstream_xchacha20poly1305_init_push(ref _state, header, key)
            : crypto_secretstream_xchacha20poly1305_init_pull(ref _state, header, key);
        if (ret != 0) { throw new CryptographicException(_encryption ? "Error initializing stream encryption." : "Error initializing stream decryption."); }
        _encryption = encryption;
        _finalized = false;
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        EncryptChunk(ciphertextChunk, plaintextChunk, associatedData: default, chunkFlag);
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (!_encryption) { throw new InvalidOperationException("Cannot encrypt on a decryption stream."); }
        if (_finalized) { throw new InvalidOperationException("Cannot encrypt after the final chunk without reinitializing."); }
        Validation.EqualTo($"{nameof(ciphertextChunk)}.{nameof(ciphertextChunk.Length)}", ciphertextChunk.Length, plaintextChunk.Length + TagSize);
        int ret = crypto_secretstream_xchacha20poly1305_push(ref _state, ciphertextChunk, ciphertextChunkLength: out _, plaintextChunk, (ulong)plaintextChunk.Length, associatedData, (ulong)associatedData.Length, (byte)chunkFlag);
        if (ret != 0) { throw new CryptographicException("Error encrypting plaintext chunk."); }
        if (chunkFlag == ChunkFlag.Final) { _finalized = true; }
    }

    public ChunkFlag DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (_encryption) { throw new InvalidOperationException("Cannot decrypt on an encryption stream."); }
        if (_finalized) { throw new InvalidOperationException("Cannot decrypt after the final chunk without reinitializing."); }
        Validation.GreaterThanOrEqualTo($"{nameof(ciphertextChunk)}.{nameof(ciphertextChunk.Length)}", ciphertextChunk.Length, TagSize);
        Validation.EqualTo($"{nameof(plaintextChunk)}.{nameof(plaintextChunk.Length)}", plaintextChunk.Length, ciphertextChunk.Length - TagSize);
        int ret = crypto_secretstream_xchacha20poly1305_pull(ref _state, plaintextChunk, plaintextChunkLength: out _, out byte chunkFlag, ciphertextChunk, (ulong)ciphertextChunk.Length, associatedData, (ulong)associatedData.Length);
        if (ret != 0) { throw new CryptographicException("Invalid chunk authentication tag for the given inputs."); }
        if (chunkFlag == (byte)ChunkFlag.Final) { _finalized = true; }
        return (ChunkFlag)chunkFlag;
    }

    public void Rekey()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot rekey after the final chunk without reinitializing."); }
        crypto_secretstream_xchacha20poly1305_rekey(ref _state);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private unsafe void Dispose(bool disposing)
    {
        if (_disposed) { return; }
        fixed (void* s = &_state) {
            SecureMemory.ZeroMemory(new Span<byte>(s, Marshal.SizeOf(_state)));
        }
        if (_stateHandle.IsAllocated) { _stateHandle.Free(); }
        _disposed = true;
    }

    ~IncrementalXChaCha20Poly1305()
    {
        Dispose(false);
    }
}
