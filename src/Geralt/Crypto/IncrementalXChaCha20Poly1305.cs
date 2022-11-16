using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalXChaCha20Poly1305 : IDisposable
{
    private crypto_secretstream_xchacha20poly1305_state _state;
    private readonly bool _decryption;
    
    public const int KeySize = crypto_secretstream_xchacha20poly1305_KEYBYTES;
    public const int HeaderSize = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    public const int TagSize = crypto_secretstream_xchacha20poly1305_ABYTES;

    public enum StreamFlag
    {
        Message = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
        Push = crypto_secretstream_xchacha20poly1305_TAG_PUSH,
        Rekey = crypto_secretstream_xchacha20poly1305_TAG_REKEY,
        Final = crypto_secretstream_xchacha20poly1305_TAG_FINAL
    }

    public IncrementalXChaCha20Poly1305(bool decryption, Span<byte> header, ReadOnlySpan<byte> key)
    {
        _decryption = decryption;
        Validation.EqualToSize(nameof(header), header.Length, HeaderSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Sodium.Initialise();
        Initialize(header, key);
    }

    private unsafe void Initialize(Span<byte> header, ReadOnlySpan<byte> key)
    {
        fixed (byte* k = key, h = header)
        {
            int ret = _decryption
                ? crypto_secretstream_xchacha20poly1305_init_pull(ref _state, h, k)
                : crypto_secretstream_xchacha20poly1305_init_push(ref _state, h, k);
            if (ret != 0) { throw new CryptographicException(_decryption ? "Error initialising stream decryption." : "Error initialising stream encryption."); }
        }
    }

    public unsafe void Push(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> associatedData = default, StreamFlag streamFlag = StreamFlag.Message)
    {
        if (_decryption) { throw new InvalidOperationException("Cannot push into a decryption stream."); }
        Validation.EqualToSize(nameof(ciphertextChunk), ciphertextChunk.Length, plaintextChunk.Length + TagSize);
        fixed (byte* c = ciphertextChunk, p = plaintextChunk, a = associatedData)
        {
            int ret = crypto_secretstream_xchacha20poly1305_push(ref _state, c, out _, p, (ulong)plaintextChunk.Length, a, (ulong)associatedData.Length, (byte)streamFlag);
            if (ret != 0) { throw new CryptographicException("Error encrypting plaintext chunk."); }
        }
    }

    public unsafe StreamFlag Pull(Span<byte> plaintextChunk, ReadOnlySpan<byte> ciphertextChunk, ReadOnlySpan<byte> associatedData = default)
    {
        if (!_decryption) { throw new InvalidOperationException("Cannot pull from an encryption stream."); }
        Validation.EqualToSize(nameof(plaintextChunk), plaintextChunk.Length, ciphertextChunk.Length - TagSize);
        fixed (byte* p = plaintextChunk, c = ciphertextChunk, a = associatedData)
        {
            int ret = crypto_secretstream_xchacha20poly1305_pull(ref _state, p, out _, out byte streamFlag, c, (ulong)ciphertextChunk.Length, a, (ulong)associatedData.Length);
            if (ret != 0) { throw new CryptographicException("Error decrypting ciphertext chunk."); }
            return (StreamFlag)streamFlag;
        }
    }

    public void Rekey()
    {
        crypto_secretstream_xchacha20poly1305_rekey(ref _state);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}