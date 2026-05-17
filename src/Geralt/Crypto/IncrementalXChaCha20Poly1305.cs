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

    private unsafe void* _state;
    private int _encryption;
    private int _finalized;
    private int _disposed;

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
        Reinitialize(header, key, encryption);
    }

    public unsafe void Reinitialize(Span<byte> header, ReadOnlySpan<byte> key, bool encryption)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        Validation.EqualTo($"{nameof(header)}.{nameof(header.Length)}", header.Length, HeaderSize);
        Validation.EqualTo($"{nameof(key)}.{nameof(key.Length)}", key.Length, KeySize);
        if (_state == null) {
            _state = NativeMemory.Alloc(crypto_secretstream_xchacha20poly1305_statebytes);
        }
        int ret = encryption
            ? crypto_secretstream_xchacha20poly1305_init_push(_state, header, key)
            : crypto_secretstream_xchacha20poly1305_init_pull(_state, header, key);
        if (ret != 0) { throw new CryptographicException(encryption ? "Error initializing stream encryption." : "Error initializing stream decryption."); }
        Interlocked.Exchange(ref _encryption, encryption ? 1 : 0);
        Interlocked.Exchange(ref _finalized, 0);
    }

    public void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        EncryptChunk(ciphertextChunk, plaintextChunk, associatedData: default, chunkFlag);
    }

    public unsafe void EncryptChunk(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData, ChunkFlag chunkFlag = ChunkFlag.Message)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (Interlocked.CompareExchange(ref _encryption, value: 1, comparand: 1) != 1) { throw new InvalidOperationException("Cannot encrypt on a decryption stream."); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot encrypt after the final chunk without reinitializing."); }
        Validation.EqualTo($"{nameof(ciphertextChunk)}.{nameof(ciphertextChunk.Length)}", ciphertextChunk.Length, plaintextChunk.Length + TagSize);
        if (!Enum.IsDefined(chunkFlag)) { throw new ArgumentOutOfRangeException(nameof(chunkFlag), chunkFlag, $"{nameof(chunkFlag)} must be a value within the enum."); }
        int ret = crypto_secretstream_xchacha20poly1305_push(_state, ciphertextChunk, ciphertextChunkLength: out _, plaintextChunk, (ulong)plaintextChunk.Length, associatedData, (ulong)associatedData.Length, (byte)chunkFlag);
        if (ret != 0) { throw new CryptographicException("Error encrypting plaintext chunk."); }
        if (chunkFlag == ChunkFlag.Final) { Interlocked.Exchange(ref _finalized, 1); }
    }

    public unsafe ChunkFlag DecryptChunk(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData = default)
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (Interlocked.CompareExchange(ref _encryption, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot decrypt on an encryption stream."); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot decrypt after the final chunk without reinitializing."); }
        Validation.GreaterThanOrEqualTo($"{nameof(ciphertextChunk)}.{nameof(ciphertextChunk.Length)}", ciphertextChunk.Length, TagSize);
        Validation.EqualTo($"{nameof(plaintextChunk)}.{nameof(plaintextChunk.Length)}", plaintextChunk.Length, ciphertextChunk.Length - TagSize);
        int ret = crypto_secretstream_xchacha20poly1305_pull(_state, plaintextChunk, plaintextChunkLength: out _, out byte chunkFlag, ciphertextChunk, (ulong)ciphertextChunk.Length, associatedData, (ulong)associatedData.Length);
        if (ret != 0) { throw new CryptographicException("Invalid chunk authentication tag for the given inputs."); }
        if (chunkFlag == (byte)ChunkFlag.Final) { Interlocked.Exchange(ref _finalized, 1); }
        return (ChunkFlag)chunkFlag;
    }

    public unsafe void Rekey()
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(IncrementalXChaCha20Poly1305)); }
        if (Interlocked.CompareExchange(ref _finalized, value: 1, comparand: 1) != 0) { throw new InvalidOperationException("Cannot rekey after the final chunk without reinitializing."); }
        crypto_secretstream_xchacha20poly1305_rekey(_state);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private unsafe void Dispose(bool disposing)
    {
        // If _disposed is 0, set to 1
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 0) != 0) { return; }
        if (_state != null) {
            SecureMemory.ZeroMemory(new Span<byte>(_state, crypto_secretstream_xchacha20poly1305_statebytes));
            NativeMemory.Free(_state);
            _state = null;
        }
    }

    ~IncrementalXChaCha20Poly1305()
    {
        Dispose(false);
    }
}
