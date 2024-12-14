using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalXChaCha20Poly1305 : IDisposable
{
    public const int KeySize = crypto_secretstream_xchacha20poly1305_KEYBYTES;
    public const int HeaderSize = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    public const int TagSize = crypto_secretstream_xchacha20poly1305_ABYTES;

    private crypto_secretstream_xchacha20poly1305_state _state;
    private bool _decryption;
    private bool _finalized;
    private bool _disposed;

    public enum ChunkFlag
    {
        Message = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
        Boundary = crypto_secretstream_xchacha20poly1305_TAG_PUSH,
        Rekey = crypto_secretstream_xchacha20poly1305_TAG_REKEY,
        Final = crypto_secretstream_xchacha20poly1305_TAG_FINAL
    }

    public IncrementalXChaCha20Poly1305(bool decryption, Span<byte> header, ReadOnlySpan<byte> key)
    {
        Sodium.Initialize();
        Reinitialize(decryption, header, key);
    }

    public void Reinitialize(bool decryption, Span<byte> header, ReadOnlySpan<byte> key)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        _decryption = decryption;
        _finalized = false;
        int ret = _decryption
            ? crypto_secretstream_xchacha20poly1305_init_pull(ref _state, header, key)
            : crypto_secretstream_xchacha20poly1305_init_push(ref _state, header, key);
        if (ret != 0) { throw new CryptographicException(_decryption ? "Error initializing stream decryption." : "Error initializing stream encryption."); }
    }

    public void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        Push(ciphertextChunk, plaintextChunk, associatedData: default, chunkFlag);
    }

    public void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (_decryption) { throw new InvalidOperationException("Cannot push into a decryption stream."); }
        if (_finalized) { throw new InvalidOperationException("Cannot push after the final chunk without reinitializing."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);
        if (chunkFlag == ChunkFlag.Final) { _finalized = true; }
        int ret = crypto_secretstream_xchacha20poly1305_push(ref _state, ciphertextChunk, out _, plaintextChunk, (ulong)plaintextChunk.Length, associatedData, (ulong)associatedData.Length, (byte)chunkFlag);
        if (ret != 0) { throw new CryptographicException("Error encrypting plaintext chunk."); }
    }

    public ChunkFlag Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData = default)
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (!_decryption) { throw new InvalidOperationException("Cannot pull from an encryption stream."); }
        if (_finalized) { throw new InvalidOperationException("Cannot pull after the final chunk without reinitializing."); }
        Validation.NotLessThanMin(nameof(ciphertextChunk), ciphertextChunk.Length, TagSize);
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);
        int ret = crypto_secretstream_xchacha20poly1305_pull(ref _state, plaintextChunk, out _, out byte chunkFlag, ciphertextChunk, (ulong)ciphertextChunk.Length, associatedData, (ulong)associatedData.Length);
        if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext chunk."); }
        if (chunkFlag == (byte)ChunkFlag.Final) { _finalized = true; }
        return (ChunkFlag)chunkFlag;
    }

    public void Rekey()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (_finalized) { throw new InvalidOperationException("Cannot rekey after the final chunk without reinitializing."); }
        crypto_secretstream_xchacha20poly1305_rekey(ref _state);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public void Dispose()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        _state = default;
        _disposed = true;
    }
}
